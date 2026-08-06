import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.check_litellm_global_config import (
    REQUIRED_SETTINGS,
    ReconcileError,
    check_actual_config,
    check_coolify_mount,
    check_remote_configs,
    governed_settings,
    load_contract,
    read_remote_configs,
    settings_digest,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/litellm-global-config.json"
SOURCE = ROOT / "config/litellm-global-settings.yaml"


class FakeCoolify:
    def __init__(self, payload):
        self.payload = copy.deepcopy(payload)
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        return copy.deepcopy(self.payload)


def service_payload(contract):
    mount = contract.mount
    return {
        "uuid": mount.service_uuid,
        "name": "human-readable-name-is-not-a-mount-identity",
        "docker_compose_raw": "\n".join(
            [
                "services:",
                "  litellm:",
                "    volumes:",
                "      - type: bind",
                f"        source: {mount.compose_source}",
                f"        target: {mount.container_target}",
            ]
        ),
        "docker_compose": "\n".join(
            [
                "services:",
                "  litellm:",
                f"    container_name: {mount.container_name}",
                "    volumes:",
                f"      - '{mount.host_source}:{mount.container_target}'",
            ]
        ),
    }


class GlobalSettingsTests(unittest.TestCase):
    def test_source_is_exact_and_digest_is_current(self):
        contract = load_contract(CONTRACT, ROOT)
        self.assertEqual(governed_settings(SOURCE.read_text()), REQUIRED_SETTINGS)
        self.assertEqual(
            contract.semantic_digest,
            "sha256:1c0e60bca81fe2b85f00191e895a2d94c0e515f9c405bead0aa086185810d927",
        )

    def test_stale_digest_is_refused(self):
        raw = json.loads(CONTRACT.read_text())
        raw["settingsSemanticDigest"] = "sha256:" + "0" * 64
        raw["settingsSource"] = "settings.yaml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "settings.yaml").write_text(SOURCE.read_text())
            path = root / "contract.json"
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(ReconcileError, "digest is stale"):
                load_contract(path, root)

    def test_missing_false_or_nonzero_settings_fail_closed(self):
        contract = load_contract(CONTRACT, ROOT)
        cases = (
            "litellm_settings:\n  include_cost_in_streaming_usage: true\n",
            SOURCE.read_text().replace("drop_params: false", "drop_params: true"),
            SOURCE.read_text().replace("num_retries: 0", "num_retries: 2"),
            SOURCE.read_text().replace("max_fallbacks: 0", "max_fallbacks: 1"),
        )
        for actual in cases:
            with self.subTest(actual=actual):
                with self.assertRaisesRegex(ReconcileError, "global config drift"):
                    check_actual_config(contract, actual)

    def test_unrelated_config_and_secrets_are_ignored_and_never_reported(self):
        contract = load_contract(CONTRACT, ROOT)
        secret = "sk-secret-that-must-not-escape"
        actual = SOURCE.read_text() + f"\ngeneral_settings:\n  master_key: {secret}\n"
        report = check_actual_config(contract, actual)
        self.assertEqual(report["status"], "current")
        self.assertNotIn(secret, json.dumps(report))

    def test_duplicate_governed_setting_is_refused(self):
        actual = SOURCE.read_text().replace(
            "  drop_params: false", "  drop_params: false\n  drop_params: false"
        )
        with self.assertRaisesRegex(ReconcileError, "duplicate YAML mapping key"):
            governed_settings(actual)

    def test_duplicate_governed_section_in_inline_or_block_form_is_refused(self):
        cases = (
            SOURCE.read_text()
            + "router_settings: {num_retries: 7, max_fallbacks: 9}\n",
            SOURCE.read_text()
            + "router_settings:\n  num_retries: 7\n  max_fallbacks: 9\n",
        )
        for actual in cases:
            with self.subTest(actual=actual):
                with self.assertRaisesRegex(
                    ReconcileError, "duplicate YAML mapping key"
                ):
                    governed_settings(actual)

    def test_duplicate_governed_inline_key_is_refused(self):
        actual = """\
litellm_settings: {include_cost_in_streaming_usage: true, drop_params: false}
router_settings: {num_retries: 0, num_retries: 7, max_fallbacks: 0}
"""
        with self.assertRaisesRegex(ReconcileError, "duplicate YAML mapping key"):
            governed_settings(actual)

    def test_invalid_plain_scalars_anywhere_fail_closed(self):
        for invalid in ("@invalid", "`invalid", ": invalid"):
            actual = SOURCE.read_text() + f"\ngeneral_settings:\n  unrelated: {invalid}\n"
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ReconcileError, "invalid plain YAML scalar"):
                    governed_settings(actual)

    def test_valid_plain_command_flag_outside_policy_is_accepted(self):
        actual = SOURCE.read_text() + "\ngeneral_settings:\n  command_flag: --config\n"
        self.assertEqual(governed_settings(actual), REQUIRED_SETTINGS)

    def test_duplicate_arbitrary_key_never_leaks_its_name(self):
        secret_key = "sk-sensitive-value-as-key"
        actual = SOURCE.read_text() + (
            f"\ngeneral_settings:\n  {secret_key}: first\n  {secret_key}: second\n"
        )
        with self.assertRaises(ReconcileError) as raised:
            governed_settings(actual)
        self.assertNotIn(secret_key, str(raised.exception))

    def test_ambiguous_governed_structures_and_types_are_refused(self):
        cases = (
            SOURCE.read_text().replace(
                "router_settings:\n  num_retries: 0\n  max_fallbacks: 0",
                "router_settings: [0, 0]",
            ),
            SOURCE.read_text().replace("drop_params: false", "drop_params: 'false'"),
            SOURCE.read_text().replace("num_retries: 0", "num_retries: false"),
        )
        for actual in cases:
            with self.subTest(actual=actual):
                with self.assertRaisesRegex(ReconcileError, "must be|invalid YAML type"):
                    governed_settings(actual)

    def test_semantic_digest_ignores_yaml_order_comments_and_whitespace(self):
        reordered = """\
router_settings:   # order is intentionally different
  max_fallbacks: 0
  num_retries: 0
litellm_settings:
  drop_params: false
  include_cost_in_streaming_usage: true
"""
        self.assertEqual(governed_settings(reordered), REQUIRED_SETTINGS)
        self.assertEqual(
            settings_digest(governed_settings(reordered)),
            settings_digest(governed_settings(SOURCE.read_text())),
        )

    def test_valid_inline_policy_is_accepted(self):
        inline = """\
litellm_settings: {include_cost_in_streaming_usage: true, drop_params: false}
router_settings: {num_retries: 0, max_fallbacks: 0}
"""
        self.assertEqual(governed_settings(inline), REQUIRED_SETTINGS)


class CoolifyMountTests(unittest.TestCase):
    def test_exact_service_and_mount_are_current(self):
        contract = load_contract(CONTRACT, ROOT)
        client = FakeCoolify(service_payload(contract))
        report = check_coolify_mount(contract, client)
        self.assertEqual(
            report,
            {"status": "current", "serviceUuid": contract.mount.service_uuid},
        )
        self.assertEqual(client.paths, [f"/services/{contract.mount.service_uuid}"])

    def test_mount_drift_is_refused_without_returning_compose(self):
        contract = load_contract(CONTRACT, ROOT)
        payload = service_payload(contract)
        payload["docker_compose"] = payload["docker_compose"].replace(
            contract.mount.container_target, "/tmp/other.yaml"
        )
        with self.assertRaises(ReconcileError) as raised:
            check_coolify_mount(contract, FakeCoolify(payload))
        self.assertNotIn(payload["docker_compose"], str(raised.exception))

    def test_comments_and_environment_lures_do_not_satisfy_identity_or_mount(self):
        contract = load_contract(CONTRACT, ROOT)
        mount = contract.mount
        payload = service_payload(contract)
        payload["docker_compose"] = "\n".join(
            [
                "services:",
                "  litellm:",
                "    container_name: wrong-container",
                "    environment:",
                f"      LURE_CONTAINER: 'container_name: {mount.container_name}'",
                f"      LURE_VOLUME: '{mount.host_source}:{mount.container_target}'",
                f"    # container_name: {mount.container_name}",
                f"    # - '{mount.host_source}:{mount.container_target}'",
                "    volumes:",
                "      - '/tmp/wrong.yaml:/app/wrong.yaml'",
            ]
        )
        with self.assertRaisesRegex(ReconcileError, "container identity drift"):
            check_coolify_mount(contract, FakeCoolify(payload))

    def test_identity_and_mount_split_across_services_are_refused(self):
        contract = load_contract(CONTRACT, ROOT)
        mount = contract.mount
        payload = service_payload(contract)
        payload["docker_compose_raw"] = "\n".join(
            [
                "services:",
                "  litellm:",
                "    volumes:",
                f"      - '{mount.compose_source}:{mount.container_target}'",
                "  lure:",
                "    volumes:",
                "      - '/tmp/wrong.yaml:/app/config.yaml'",
            ]
        )
        payload["docker_compose"] = "\n".join(
            [
                "services:",
                "  litellm:",
                "    container_name: wrong-container",
                "    volumes:",
                f"      - '{mount.host_source}:{mount.container_target}'",
                "  lure:",
                f"    container_name: {mount.container_name}",
                "    volumes:",
                f"      - '{mount.host_source}:{mount.container_target}'",
            ]
        )
        with self.assertRaisesRegex(ReconcileError, "container identity drift"):
            check_coolify_mount(contract, FakeCoolify(payload))

    def test_raw_mount_on_a_different_service_is_refused(self):
        contract = load_contract(CONTRACT, ROOT)
        mount = contract.mount
        payload = service_payload(contract)
        payload["docker_compose_raw"] = "\n".join(
            [
                "services:",
                "  litellm:",
                "    volumes:",
                "      - '/tmp/wrong.yaml:/app/config.yaml'",
                "  lure:",
                "    volumes:",
                f"      - '{mount.compose_source}:{mount.container_target}'",
            ]
        )
        with self.assertRaisesRegex(ReconcileError, "source mount drift"):
            check_coolify_mount(contract, FakeCoolify(payload))

    def test_wrong_rendered_volume_source_or_target_is_refused(self):
        contract = load_contract(CONTRACT, ROOT)
        for old, new in (
            (contract.mount.host_source, "/tmp/wrong.yaml"),
            (contract.mount.container_target, "/app/wrong.yaml"),
        ):
            payload = service_payload(contract)
            payload["docker_compose"] = payload["docker_compose"].replace(old, new)
            with self.subTest(new=new):
                with self.assertRaisesRegex(ReconcileError, "rendered mount drift"):
                    check_coolify_mount(contract, FakeCoolify(payload))

    def test_duplicate_mount_target_is_refused_even_when_one_bind_is_exact(self):
        contract = load_contract(CONTRACT, ROOT)
        mount = contract.mount
        for volumes in (
            [
                f"      - '{mount.host_source}:{mount.container_target}'",
                f"      - '/tmp/wrong.yaml:{mount.container_target}'",
            ],
            [
                f"      - '/tmp/wrong.yaml:{mount.container_target}'",
                f"      - '{mount.host_source}:{mount.container_target}'",
            ],
        ):
            payload = service_payload(contract)
            payload["docker_compose"] = "\n".join(
                [
                    "services:",
                    "  litellm:",
                    f"    container_name: {mount.container_name}",
                    "    volumes:",
                    *volumes,
                ]
            )
            with self.subTest(volumes=volumes):
                with self.assertRaisesRegex(ReconcileError, "rendered mount drift"):
                    check_coolify_mount(contract, FakeCoolify(payload))

    def test_long_syntax_rendered_bind_is_current(self):
        contract = load_contract(CONTRACT, ROOT)
        mount = contract.mount
        payload = service_payload(contract)
        payload["docker_compose"] = "\n".join(
            [
                "services:",
                "  litellm:",
                f"    container_name: {mount.container_name}",
                "    volumes:",
                "      - type: bind",
                f"        source: {mount.host_source}",
                f"        target: {mount.container_target}",
                "        read_only: true",
            ]
        )
        self.assertEqual(
            check_coolify_mount(contract, FakeCoolify(payload))["status"], "current"
        )

    def test_duplicate_compose_service_key_is_refused(self):
        contract = load_contract(CONTRACT, ROOT)
        payload = service_payload(contract)
        payload["docker_compose"] += "\n  litellm:\n    container_name: duplicate\n"
        with self.assertRaisesRegex(ReconcileError, "duplicate YAML mapping key"):
            check_coolify_mount(contract, FakeCoolify(payload))

    @patch("scripts.check_litellm_global_config.subprocess.run")
    def test_remote_reads_use_argv_strict_host_key_sudo_and_hide_stderr(self, run):
        contract = load_contract(CONTRACT, ROOT)
        run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=SOURCE.read_bytes(), stderr=b""
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout=SOURCE.read_bytes(), stderr=b""
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "identity"
            known_hosts = Path(directory) / "known_hosts"
            identity.touch()
            known_hosts.touch()
            mounted, runtime = read_remote_configs(
                contract, "coolify.example.test", 6969, identity, known_hosts
            )
        self.assertEqual((mounted, runtime), (SOURCE.read_text(), SOURCE.read_text()))
        mounted_command = run.call_args_list[0].args[0]
        runtime_command = run.call_args_list[1].args[0]
        for call in run.call_args_list:
            self.assertIn("StrictHostKeyChecking=yes", call.args[0])
            self.assertEqual(call.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(
            mounted_command[-4:],
            ["sudo", "-n", "cat", contract.mount.host_source],
        )
        self.assertEqual(
            runtime_command[-7:],
            [
                "sudo",
                "-n",
                "docker",
                "exec",
                contract.mount.container_name,
                "cat",
                contract.mount.container_target,
            ],
        )

    def test_host_and_runtime_must_be_byte_identical_without_secret_output(self):
        contract = load_contract(CONTRACT, ROOT)
        secret = "secret-host-only-value"
        mounted = SOURCE.read_text() + f"\ngeneral_settings:\n  master_key: {secret}\n"
        runtime = SOURCE.read_text() + "\ngeneral_settings:\n  master_key: different\n"
        with self.assertRaises(ReconcileError) as raised:
            check_remote_configs(contract, mounted, runtime)
        self.assertNotIn(secret, str(raised.exception))

    def test_host_and_runtime_policy_and_bytes_match(self):
        contract = load_contract(CONTRACT, ROOT)
        actual = SOURCE.read_text() + "\ngeneral_settings:\n  master_key: redacted-test-value\n"
        self.assertEqual(
            check_remote_configs(contract, actual, actual),
            {
                "status": "current",
                "settingsSemanticDigest": contract.semantic_digest,
            },
        )


if __name__ == "__main__":
    unittest.main()

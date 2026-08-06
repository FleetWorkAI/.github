import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts.reconcile_litellm_keys import (
    ReconcileError,
    Sink,
    drift_fields,
    index_managed_keys,
    inspect_secret_sinks,
    load_config,
    reconcile,
    smoke_workload_keys,
    write_github_secret,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config/litellm-workload-keys.json"
CATALOG = ROOT / "tests/fixtures/catalog.v1.json"
SECRET = "sk-fleetwork-test-secret-never-print"


class FakeLiteLLM:
    def __init__(self, rows, fail_create_after_write=False, fail_delete_call=None):
        self.rows = copy.deepcopy(rows)
        self.calls = []
        self.fail_create_after_write = fail_create_after_write
        self.generate_count = 0
        self.fail_delete_call = fail_delete_call
        self.delete_count = 0

    def get(self, path):
        self.calls.append(("GET", path))
        if path.startswith("/key/list?"):
            return {"keys": copy.deepcopy(self.rows), "total_pages": 1}
        raise AssertionError(f"unexpected GET {path}")

    def post(self, path, payload):
        self.calls.append(("POST", path, copy.deepcopy(payload)))
        if path == "/key/generate":
            self.generate_count += 1
            secret = SECRET if self.generate_count == 1 else f"{SECRET}-{self.generate_count}"
            row = copy.deepcopy(payload)
            row["token"] = hashlib.sha256(secret.encode()).hexdigest()
            self.rows.append(row)
            if self.fail_create_after_write:
                raise ReconcileError("POST /key/generate is unavailable")
            return {"key": secret}
        if path == "/key/update":
            identifier = payload["key"]
            row = next(row for row in self.rows if row["token"] == identifier)
            row.update({key: copy.deepcopy(value) for key, value in payload.items() if key != "key"})
            return {"status": "ok"}
        if path == "/key/delete":
            self.delete_count += 1
            if self.delete_count == self.fail_delete_call:
                raise ReconcileError("POST /key/delete is unavailable")
            identifiers = set(payload["keys"])
            self.rows = [row for row in self.rows if row["token"] not in identifiers]
            return {"deleted_keys": len(identifiers)}
        raise AssertionError(f"unexpected POST {path}")


class FakeCoolify:
    def __init__(self, fail_write=False):
        self.rows = []
        self.calls = []
        self.fail_write = fail_write

    def get(self, path):
        self.calls.append(("GET", path))
        return copy.deepcopy(self.rows)

    def post(self, path, payload):
        self.calls.append(("POST", path, {**payload, "value": "[redacted]"}))
        if self.fail_write:
            raise ReconcileError("Coolify write failed")
        self.rows.append(copy.deepcopy(payload))
        return {"message": "created"}

    def patch(self, path, payload):
        self.calls.append(("PATCH", path, {**payload, "value": "[redacted]"}))
        if self.fail_write:
            raise ReconcileError("Coolify write failed")
        match = next(
            row
            for row in self.rows
            if row["key"] == payload["key"]
            and bool(row.get("is_preview")) == bool(payload.get("is_preview"))
        )
        match.update(copy.deepcopy(payload))
        return {"message": "updated"}


class SelectiveFailCoolify(FakeCoolify):
    def __init__(self, failed_application_uuid):
        super().__init__()
        self.failed_application_uuid = failed_application_uuid

    def post(self, path, payload):
        if self.failed_application_uuid in path:
            raise ReconcileError("Coolify write failed")
        return super().post(path, payload)

    def patch(self, path, payload):
        if self.failed_application_uuid in path:
            raise ReconcileError("Coolify write failed")
        return super().patch(path, payload)


class SmokeCoolify:
    def __init__(self, workloads):
        self.by_path = {}
        for workload in workloads:
            for sink in workload.sinks:
                if sink.type == "coolify_env":
                    self.by_path.setdefault(
                        f"/applications/{sink.application_uuid}/envs", []
                    ).append(
                        {
                            "key": sink.key,
                            "value": f"{workload.id}-secret",
                            "is_preview": sink.is_preview,
                        }
                    )

    def get(self, path):
        return copy.deepcopy(self.by_path.get(path, []))


class FakeSmokeHttp:
    def __init__(self, statuses=None):
        self.statuses = iter(
            statuses
            or [200, 200, 403, 200, 403, 403, 200, 200, 403, 403, 200, 403, 403]
        )
        self.calls = []

    def request(self, base_url, key, method, path, payload=None):
        self.calls.append((base_url, "[redacted]", method, path, copy.deepcopy(payload)))
        return next(self.statuses)


def loaded():
    return load_config(CONFIG, CATALOG)[1]


def current_row(workload, alias=None):
    return {
        **copy.deepcopy(workload.desired),
        "key_alias": alias or workload.key_alias,
        "token": hashlib.sha256(f"{workload.id}-secret".encode()).hexdigest(),
    }


class ConfigTests(unittest.TestCase):
    def test_config_is_bound_to_the_governed_catalog(self):
        workloads = loaded()
        self.assertEqual([workload.id for workload in workloads], [
            "runner",
            "coordinator",
            "catalog-probe",
            "spend-reader",
        ])
        self.assertEqual(workloads[1].desired["models"], ["gpt-5-nano"])
        self.assertEqual(workloads[3].desired["permissions"], {})
        self.assertEqual(workloads[3].desired["allowed_routes"], ["/spend/logs"])

    def test_catalog_version_mismatch_is_refused(self):
        raw = json.loads(CONFIG.read_text())
        raw["catalogVersion"] = "forged"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(ReconcileError, "versions do not match"):
                load_config(path, CATALOG)

    def test_duplicate_legacy_alias_is_refused(self):
        raw = json.loads(CONFIG.read_text())
        raw["workloads"][1]["legacyAliases"] = ["fleet-services"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(ReconcileError, "globally unique"):
                load_config(path, CATALOG)


class WorkloadSmokeTests(unittest.TestCase):
    def test_every_positive_and_negative_grant_is_exercised_without_secret_output(self):
        workloads = loaded()
        rows = [current_row(workload) for workload in workloads]
        indexed = index_managed_keys(rows, workloads)
        http = FakeSmokeHttp()
        report = smoke_workload_keys(
            workloads,
            indexed,
            SmokeCoolify(workloads),
            {"FLEETWORK_SMOKE_CATALOG_PROBE_KEY": "catalog-probe-secret"},
            "https://litellm.example.test",
            http,
        )
        self.assertEqual(report["status"], "smoke-passed")
        self.assertEqual(len(report["checks"]), 13)
        self.assertEqual(
            [call[3] for call in http.calls],
            [
                "/v1/chat/completions",
                "/v1/embeddings",
                "/spend/logs?request_id=fleetwork-permission-smoke-missing",
                "/v1/chat/completions",
                "/v1/chat/completions",
                "/v1/models",
                "/v1/models",
                "/v1/chat/completions",
                "/v1/embeddings",
                "/spend/logs?request_id=fleetwork-permission-smoke-missing",
                "/spend/logs?request_id=fleetwork-permission-smoke-missing",
                "/v1/chat/completions",
                "/v1/models",
            ],
        )
        self.assertEqual(http.calls[4][4]["model"], "gpt-4o")
        self.assertEqual(http.calls[8][4]["model"], "text-embedding-3-small")
        self.assertEqual(http.calls[11][4]["model"], "gpt-5-nano")

        calls = {
            check["check"]: call
            for check, call in zip(report["checks"], http.calls, strict=True)
        }
        valid_control_pairs = {
            "runner-spend-logs": "spend-reader-logs",
            "coordinator-forbidden-model": "catalog-probe-chat",
            "coordinator-model-list-refusal": "catalog-probe-models",
            "catalog-probe-embedding-refusal": "runner-embedding",
            "catalog-probe-spend-refusal": "spend-reader-logs",
            "spend-reader-chat-refusal": "runner-chat",
            "spend-reader-model-list-refusal": "catalog-probe-models",
        }
        for denied, allowed in valid_control_pairs.items():
            with self.subTest(denied=denied, allowed=allowed):
                self.assertEqual(calls[denied][2:], calls[allowed][2:])
        rendered = json.dumps({"report": report, "calls": http.calls})
        for workload in workloads:
            self.assertNotIn(f"{workload.id}-secret", rendered)

    def test_an_unexpected_allow_or_deny_status_fails_closed(self):
        workloads = loaded()
        indexed = index_managed_keys(
            [current_row(workload) for workload in workloads], workloads
        )
        with self.assertRaisesRegex(ReconcileError, "runner-spend-logs expected deny"):
            smoke_workload_keys(
                workloads,
                indexed,
                SmokeCoolify(workloads),
                {"FLEETWORK_SMOKE_CATALOG_PROBE_KEY": "catalog-probe-secret"},
                "https://litellm.example.test",
                FakeSmokeHttp([200, 200, 400]),
            )

    def test_every_negative_permission_check_requires_exact_403(self):
        workloads = loaded()
        indexed = index_managed_keys(
            [current_row(workload) for workload in workloads], workloads
        )
        expected = [200, 200, 403, 200, 403, 403, 200, 200, 403, 403, 200, 403, 403]
        denied = {
            2: "runner-spend-logs",
            4: "coordinator-forbidden-model",
            5: "coordinator-model-list-refusal",
            8: "catalog-probe-embedding-refusal",
            9: "catalog-probe-spend-refusal",
            11: "spend-reader-chat-refusal",
            12: "spend-reader-model-list-refusal",
        }
        for index, check_name in denied.items():
            statuses = expected.copy()
            statuses[index] = 400
            with self.subTest(check=check_name):
                with self.assertRaisesRegex(ReconcileError, check_name):
                    smoke_workload_keys(
                        workloads,
                        indexed,
                        SmokeCoolify(workloads),
                        {"FLEETWORK_SMOKE_CATALOG_PROBE_KEY": "catalog-probe-secret"},
                        "https://litellm.example.test",
                        FakeSmokeHttp(statuses),
                    )

    def test_a_failed_smoke_never_exposes_the_workload_secret(self):
        workloads = loaded()
        indexed = index_managed_keys(
            [current_row(workload) for workload in workloads], workloads
        )
        with self.assertRaises(ReconcileError) as raised:
            smoke_workload_keys(
                workloads,
                indexed,
                SmokeCoolify(workloads),
                {"FLEETWORK_SMOKE_CATALOG_PROBE_KEY": "catalog-probe-secret"},
                "https://litellm.example.test",
                FakeSmokeHttp([500]),
            )
        rendered = str(raised.exception)
        for workload in workloads:
            self.assertNotIn(f"{workload.id}-secret", rendered)


class ReconciliationTests(unittest.TestCase):
    def test_check_reports_only_safe_field_names(self):
        workloads = loaded()
        rows = [current_row(workload) for workload in workloads]
        rows[0]["rpm_limit"] = 1
        report = reconcile(
            "check", workloads, FakeLiteLLM(rows), verify_secret_sinks=False
        )
        self.assertEqual(report["status"], "drift")
        self.assertEqual(report["workloads"][0], {
            "workload": "runner",
            "status": "drift",
            "fields": ["rpm_limit"],
        })
        self.assertNotIn("sk-", json.dumps(report))

    def test_legacy_runner_alias_is_renamed_in_place(self):
        workloads = loaded()
        rows = [current_row(workload) for workload in workloads]
        rows[0]["key_alias"] = "fleet-services"
        rows[0]["metadata"]["purpose"] = "runner-and-coordinator"
        client = FakeLiteLLM(rows)
        report = reconcile("apply", workloads, client, verify_secret_sinks=False)
        self.assertEqual(report["status"], "applied")
        self.assertEqual(client.rows[0]["key_alias"], "fleet-runner")
        self.assertEqual(client.rows[0]["metadata"], workloads[0].desired["metadata"])
        self.assertFalse(any(call[1] == "/key/generate" for call in client.calls))

    def test_duplicate_current_and_legacy_runner_keys_are_refused(self):
        workload = loaded()[0]
        rows = [
            current_row(workload, "fleet-runner"),
            current_row(workload, "fleet-services"),
        ]
        with self.assertRaisesRegex(ReconcileError, "duplicate managed keys"):
            index_managed_keys(rows, (workload,))

    def test_managed_metadata_recovers_a_renamed_alias_in_place(self):
        workload = loaded()[0]
        row = current_row(workload, "fleet-renamed-outside-config")
        indexed = index_managed_keys([row], (workload,))
        self.assertEqual(indexed[workload.id].identifier, row["token"])

    def test_unknown_managed_workload_is_refused_as_an_orphan(self):
        workload = loaded()[0]
        row = current_row(workload)
        row["metadata"]["workload"] = "forgotten-workload"
        with self.assertRaisesRegex(ReconcileError, "unknown workload"):
            index_managed_keys([row], (workload,))

    def test_missing_key_is_created_and_written_to_coolify(self):
        workloads = loaded()
        rows = [current_row(workload) for workload in workloads[1:]]
        litellm = FakeLiteLLM(rows)
        coolify = FakeCoolify()
        report = reconcile(
            "apply",
            workloads,
            litellm,
            coolify,
            "unused",
            verify_secret_sinks=False,
        )
        self.assertEqual(report["status"], "applied")
        created = next(row for row in litellm.rows if row["key_alias"] == "fleet-runner")
        self.assertFalse(drift_fields(created, workloads[0].desired))
        self.assertEqual(len(coolify.rows), 1)
        self.assertEqual(coolify.rows[0]["key"], "LITELLM_API_KEY")
        self.assertEqual(coolify.rows[0]["value"], SECRET)

    def test_sink_failure_keeps_the_new_key_active_to_avoid_a_dead_secret(self):
        workloads = loaded()
        rows = [current_row(workload) for workload in workloads[1:]]
        litellm = FakeLiteLLM(rows)
        with self.assertRaisesRegex(ReconcileError, "kept active"):
            reconcile(
                "apply",
                workloads,
                litellm,
                FakeCoolify(fail_write=True),
                "unused",
                verify_secret_sinks=False,
            )
        self.assertTrue(any(row["key_alias"] == "fleet-runner" for row in litellm.rows))

    def test_ambiguous_create_is_discovered_and_revoked(self):
        workload = loaded()[0]
        litellm = FakeLiteLLM([], fail_create_after_write=True)
        with self.assertRaisesRegex(ReconcileError, "key/generate is unavailable"):
            reconcile(
                "apply",
                (workload,),
                litellm,
                FakeCoolify(),
                "unused",
                verify_secret_sinks=False,
            )
        self.assertEqual(litellm.rows, [])

    def test_check_detects_a_coolify_secret_fingerprint_mismatch(self):
        workload = loaded()[0]
        litellm = FakeLiteLLM([current_row(workload)])
        coolify = FakeCoolify()
        coolify.rows = [
            {"key": "LITELLM_API_KEY", "value": "wrong-secret", "is_preview": False}
        ]
        report = reconcile("check", (workload,), litellm, coolify, "unused")
        self.assertEqual(report["status"], "drift")
        self.assertEqual(report["workloads"][0]["sinks"], ["coolify:LITELLM_API_KEY"])

    def test_apply_refuses_sink_mismatch_before_any_key_mutation(self):
        workload = loaded()[0]
        litellm = FakeLiteLLM([current_row(workload)])
        coolify = FakeCoolify()
        coolify.rows = [
            {"key": "LITELLM_API_KEY", "value": "wrong-secret", "is_preview": False}
        ]
        with self.assertRaisesRegex(ReconcileError, "explicit credential rotation"):
            reconcile("apply", (workload,), litellm, coolify, "unused")
        self.assertFalse(any(call[1] in ("/key/generate", "/key/update") for call in litellm.calls))

    def test_explicit_rotation_replaces_a_mismatched_coolify_secret(self):
        workload = loaded()[0]
        old = current_row(workload)
        litellm = FakeLiteLLM([old])
        coolify = FakeCoolify()
        coolify.rows = [
            {"key": "LITELLM_API_KEY", "value": "wrong-secret", "is_preview": False}
        ]
        report = reconcile(
            "rotate",
            (workload,),
            litellm,
            coolify,
            "unused",
            rotate_workload="runner",
        )
        self.assertEqual(report["status"], "rotated")
        self.assertEqual(coolify.rows[0]["value"], SECRET)
        self.assertEqual(len(litellm.rows), 1)
        self.assertEqual(litellm.rows[0]["key_alias"], "fleet-runner")
        self.assertNotEqual(litellm.rows[0]["token"], old["token"])

    def test_failed_coolify_rotation_revokes_only_the_candidate(self):
        workload = loaded()[0]
        old = current_row(workload)
        litellm = FakeLiteLLM([old])
        coolify = FakeCoolify(fail_write=True)
        coolify.rows = [
            {"key": "LITELLM_API_KEY", "value": "wrong-secret", "is_preview": False}
        ]
        with self.assertRaisesRegex(ReconcileError, "replacement revoked"):
            reconcile(
                "rotate",
                (workload,),
                litellm,
                coolify,
                "unused",
                rotate_workload="runner",
            )
        self.assertEqual(litellm.rows, [old])

    def test_partial_multi_sink_rotation_never_revokes_a_published_candidate(self):
        base = loaded()[0]
        first = Sink("coolify_env", "LITELLM_API_KEY_A", application_uuid="app-a")
        second = Sink("coolify_env", "LITELLM_API_KEY_B", application_uuid="app-b")
        workload = replace(base, sinks=(first, second))
        old = current_row(workload)
        old_secret = f"{workload.id}-secret"
        litellm = FakeLiteLLM([old])
        coolify = SelectiveFailCoolify("app-b")
        coolify.rows = [
            {"key": first.key, "value": old_secret, "is_preview": False},
            {"key": second.key, "value": old_secret, "is_preview": False},
        ]

        with self.assertRaisesRegex(ReconcileError, "kept active"):
            reconcile(
                "rotate",
                (workload,),
                litellm,
                coolify,
                "unused",
                rotate_workload=workload.id,
            )

        candidates = [
            row
            for row in litellm.rows
            if row.get("metadata", {}).get("key_role") == "rotation_candidate"
        ]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(len(litellm.rows), 2, "old and partially published keys stay active")
        values = {row["key"]: row["value"] for row in coolify.rows}
        self.assertEqual(values[first.key], SECRET)
        self.assertEqual(values[second.key], old_secret)

        with self.assertRaisesRegex(ReconcileError, "partially published"):
            reconcile(
                "rotate",
                (workload,),
                litellm,
                coolify,
                "unused",
                rotate_workload=workload.id,
            )
        self.assertEqual(litellm.generate_count, 1, "retry must not create another candidate")

    def test_next_rotation_finishes_an_identified_published_candidate(self):
        workload = loaded()[0]
        old = current_row(workload)
        candidate_secret = "sk-fleetwork-published-candidate"
        candidate = {
            **copy.deepcopy(workload.desired),
            "key_alias": "fleet-runner-next-deadbeef",
            "metadata": {
                **copy.deepcopy(workload.desired["metadata"]),
                "key_role": "rotation_candidate",
            },
            "token": hashlib.sha256(candidate_secret.encode()).hexdigest(),
        }
        litellm = FakeLiteLLM([old, candidate])
        coolify = FakeCoolify()
        coolify.rows = [
            {
                "key": "LITELLM_API_KEY",
                "value": candidate_secret,
                "is_preview": False,
            }
        ]
        report = reconcile(
            "rotate",
            (workload,),
            litellm,
            coolify,
            "unused",
            rotate_workload="runner",
        )
        self.assertEqual(report["status"], "rotated")
        self.assertEqual(len(litellm.rows), 1)
        self.assertEqual(litellm.rows[0]["token"], candidate["token"])
        self.assertEqual(litellm.rows[0]["key_alias"], "fleet-runner")

    def test_retry_cleans_stale_candidate_without_rotating_current_again(self):
        workload = loaded()[0]
        old = current_row(workload)
        replacement_secret = "sk-fleetwork-published-replacement"
        stale_secret = "sk-fleetwork-stale-candidate"
        replacement = {
            **copy.deepcopy(workload.desired),
            "key_alias": "fleet-runner-next-replacement",
            "metadata": {
                **copy.deepcopy(workload.desired["metadata"]),
                "key_role": "rotation_candidate",
            },
            "token": hashlib.sha256(replacement_secret.encode()).hexdigest(),
        }
        stale = {
            **copy.deepcopy(replacement),
            "key_alias": "fleet-runner-next-stale",
            "token": hashlib.sha256(stale_secret.encode()).hexdigest(),
        }
        litellm = FakeLiteLLM([old, replacement, stale], fail_delete_call=2)
        coolify = FakeCoolify()
        coolify.rows = [{
            "key": "LITELLM_API_KEY",
            "value": replacement_secret,
            "is_preview": False,
        }]
        with self.assertRaisesRegex(ReconcileError, "key/delete is unavailable"):
            reconcile(
                "rotate",
                (workload,),
                litellm,
                coolify,
                "unused",
                rotate_workload="runner",
            )

        current = next(row for row in litellm.rows if row["key_alias"] == "fleet-runner")
        self.assertEqual(current["token"], replacement["token"])
        self.assertEqual(len(litellm.rows), 2)

        report = reconcile(
            "rotate",
            (workload,),
            litellm,
            coolify,
            "unused",
            rotate_workload="runner",
        )
        self.assertEqual(report["status"], "rotated")
        self.assertEqual(len(litellm.rows), 1)
        self.assertEqual(litellm.generate_count, 0)


class SecretSinkTests(unittest.TestCase):
    @patch("scripts.reconcile_litellm_keys.subprocess.run")
    def test_github_secret_is_passed_on_stdin_never_argv(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess(
                [],
                0,
                b'[{"name":"LITELLM_PROBE_KEY","updatedAt":"2026-08-05T20:00:00Z"}]',
                b"",
            ),
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    [
                        {
                            "name": "LITELLM_PROBE_KEY_SHA256",
                            "value": hashlib.sha256(SECRET.encode()).hexdigest(),
                            "updatedAt": "2026-08-05T20:00:01Z",
                        }
                    ]
                ).encode(),
                b"",
            ),
        ]
        sink = Sink(
            "github_environment_secret",
            "LITELLM_PROBE_KEY",
            repository="FleetWorkAI/.github",
            environment="production",
            fingerprint_key="LITELLM_PROBE_KEY_SHA256",
        )
        write_github_secret(sink, SECRET, "github-token")
        first = run.call_args_list[0]
        self.assertNotIn(SECRET, first.args[0])
        self.assertEqual(first.kwargs["input"], SECRET.encode())
        self.assertNotIn(SECRET, repr(first.args[0]))

    @patch("scripts.reconcile_litellm_keys.read_github_sink")
    def test_github_secret_changed_after_its_fingerprint_is_drift(self, read_sink):
        workload = loaded()[2]
        current = current_row(workload)
        read_sink.return_value = (
            {"LITELLM_PROBE_KEY": "2026-08-05T20:00:02Z"},
            {
                "LITELLM_PROBE_KEY_SHA256": {
                    "value": current["token"],
                    "updated_at": "2026-08-05T20:00:01Z",
                }
            },
        )
        drift = inspect_secret_sinks(
            (workload,),
            {workload.id: type("Current", (), {"identifier": current["token"]})()},
            None,
            "github-token",
        )
        self.assertEqual(drift, {"catalog-probe": ["github:LITELLM_PROBE_KEY"]})


if __name__ == "__main__":
    unittest.main()

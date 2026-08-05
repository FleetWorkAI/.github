import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.deploy_coolify import (
    GateError,
    Service,
    Target,
    assert_no_duplicate_env,
    deploy_target,
    load_service,
    preflight_target,
    validate_sha,
    verify_github,
)


SHA = "a" * 40


class FakeClient:
    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def get(self, path, accept="application/json"):
        self.calls.append(("GET", path))
        value = self.routes.get(("GET", path))
        if isinstance(value, tuple):
            if not value:
                raise AssertionError(f"no fake response left for {path}")
            self.routes[("GET", path)] = value[1:]
            return value[0]
        if value is None:
            raise AssertionError(f"unexpected GET {path}")
        return value

    def patch(self, path, payload):
        self.calls.append(("PATCH", path, payload))
        value = self.routes.get(("PATCH", path))
        return {} if value is None else value


def service():
    return Service(
        name="runner",
        repository="FleetWorkAI/agent-runner",
        required_checks=("cargo test", "Security"),
        targets=(Target("agent-runner", "runner-uuid", "starting runner"),),
    )


def check(name, conclusion="success", run_id=1):
    return {
        "id": run_id,
        "name": name,
        "head_sha": SHA,
        "status": "completed",
        "conclusion": conclusion,
        "app": {"slug": "github-actions"},
    }


class ConfigTests(unittest.TestCase):
    def test_sha_requires_full_commit(self):
        with self.assertRaisesRegex(GateError, "40-character"):
            validate_sha("abc123")

    def test_unknown_service_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"schemaVersion": 1, "services": {}}))
            with self.assertRaisesRegex(GateError, "not allowlisted"):
                load_service(path, "unknown")

    def test_duplicate_target_uuid_is_refused(self):
        config = {
            "schemaVersion": 1,
            "services": {
                "x": {
                    "repository": "FleetWorkAI/x",
                    "requiredChecks": ["CI"],
                    "targets": [
                        {"name": "a", "uuid": "same", "bootMarker": "ready"},
                        {"name": "b", "uuid": "same", "bootMarker": "ready"},
                    ],
                }
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(GateError, "more than once"):
                load_service(path, "x")


class GithubGateTests(unittest.TestCase):
    def github(self, checks, main_sha=SHA, total_count=None):
        repo = "/repos/FleetWorkAI/agent-runner"
        return FakeClient(
            {
                ("GET", f"{repo}/commits/main"): {"sha": main_sha},
                ("GET", f"{repo}/commits/{SHA}/check-runs?filter=latest&per_page=100"): {
                    "total_count": len(checks) if total_count is None else total_count,
                    "check_runs": checks,
                },
            }
        )

    def test_current_main_with_green_checks_passes(self):
        verify_github(self.github([check("cargo test"), check("Security")]), service(), SHA)

    def test_sha_other_than_main_is_refused(self):
        with self.assertRaisesRegex(GateError, "not the current main"):
            verify_github(self.github([], main_sha="b" * 40), service(), SHA)

    def test_missing_or_failed_check_is_refused(self):
        with self.assertRaisesRegex(GateError, "cargo test: completed/failure, Security: missing"):
            verify_github(self.github([check("cargo test", "failure")]), service(), SHA)

    def test_latest_rerun_is_authoritative(self):
        runs = [check("cargo test", "failure", 1), check("cargo test", "success", 2), check("Security")]
        verify_github(self.github(runs), service(), SHA)

    def test_incomplete_check_page_is_refused(self):
        with self.assertRaisesRegex(GateError, "incomplete evaluation"):
            verify_github(self.github([check("cargo test")], total_count=101), service(), SHA)


class CoolifyGateTests(unittest.TestCase):
    def test_duplicate_environment_keys_are_refused_without_values(self):
        client = FakeClient({("GET", "/applications/runner-uuid/envs"): [
            {"key": "TOKEN", "value": "first", "is_preview": False},
            {"key": "TOKEN", "value": "second", "is_preview": False},
        ]})
        with self.assertRaisesRegex(GateError, r"TOKEN\[production\]"):
            assert_no_duplicate_env(client, service().targets[0])

    def test_production_and_preview_rows_are_distinct_scopes(self):
        client = FakeClient({("GET", "/applications/runner-uuid/envs"): [
            {"key": "TOKEN", "value": "production", "is_preview": False},
            {"key": "TOKEN", "value": "preview", "is_preview": True},
        ]})
        assert_no_duplicate_env(client, service().targets[0])

    def test_preflight_refuses_a_repository_mismatch_without_mutation(self):
        client = FakeClient({("GET", "/applications/runner-uuid"): {
            "name": "agent-runner",
            "git_repository": "FleetWorkAI/wrong",
            "git_branch": "main",
        }})
        with self.assertRaisesRegex(GateError, "repository mismatch"):
            preflight_target(client, service(), service().targets[0])
        self.assertFalse(any(call[0] == "PATCH" for call in client.calls))

    @patch("scripts.deploy_coolify.time.sleep", return_value=None)
    def test_deploy_pins_sha_and_proves_fresh_boot(self, _sleep):
        app_before = {
            "name": "agent-runner",
            "git_repository": "FleetWorkAI/agent-runner",
            "git_branch": "main",
            "git_commit_sha": "HEAD",
            "last_restart_at": "before",
            "status": "running:healthy",
        }
        app_after = {**app_before, "git_commit_sha": SHA, "last_restart_at": "after"}
        client = FakeClient(
            {
                ("GET", "/applications/runner-uuid"): (app_before, app_after, app_after),
                ("GET", "/applications/runner-uuid/envs"): [{"key": "ONE"}],
                ("GET", "/deploy?uuid=runner-uuid&force=false"): {"deployment_uuid": "dep-1"},
                ("GET", "/deployments/dep-1"): {"status": "finished", "commit": SHA},
                ("GET", "/applications/runner-uuid/logs?lines=200"): {
                    "logs": "starting runner"
                },
            }
        )
        deploy_id = deploy_target(client, service(), service().targets[0], SHA, 1, 0)
        self.assertEqual(deploy_id, "dep-1")
        self.assertIn(("PATCH", "/applications/runner-uuid", {"git_commit_sha": SHA}), client.calls)

    @patch("scripts.deploy_coolify.time.sleep", return_value=None)
    def test_deployment_commit_mismatch_is_refused(self, _sleep):
        app = {
            "name": "agent-runner",
            "git_repository": "FleetWorkAI/agent-runner",
            "git_branch": "main",
            "git_commit_sha": SHA,
            "last_restart_at": "before",
            "status": "running:healthy",
        }
        client = FakeClient(
            {
                ("GET", "/applications/runner-uuid"): (app, app),
                ("GET", "/applications/runner-uuid/envs"): [],
                ("GET", "/deploy?uuid=runner-uuid&force=false"): {"deployment_uuid": "dep-1"},
                ("GET", "/deployments/dep-1"): {"status": "finished", "commit": "b" * 40},
            }
        )
        with self.assertRaisesRegex(GateError, "did not prove commit"):
            deploy_target(client, service(), service().targets[0], SHA, 1, 0)


if __name__ == "__main__":
    unittest.main()

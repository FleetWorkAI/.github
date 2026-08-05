import json
import tempfile
import unittest
from pathlib import Path

from scripts.deploy_coolify import GateError
from scripts.merge_checked_pr import RepositoryPolicy, load_policy, merge_pr


SHA = "a" * 40
MERGE_SHA = "b" * 40


def check(name, conclusion="success"):
    return {
        "id": 1,
        "name": name,
        "head_sha": SHA,
        "status": "completed",
        "conclusion": conclusion,
        "app": {"slug": "github-actions"},
    }


class FakeGithub:
    def __init__(self, pull=None, checks=None, merge=None):
        self.pull = pull or {
            "state": "open",
            "draft": False,
            "mergeable": True,
            "base": {"ref": "main"},
            "head": {"sha": SHA},
        }
        self.checks = checks or [check("CI"), check("Security")]
        self.merge = merge or {"merged": True, "sha": MERGE_SHA}
        self.calls = []

    def get(self, path, accept="application/json"):
        self.calls.append(("GET", path))
        if path.endswith("/pulls/12"):
            return self.pull
        if "/check-runs?" in path:
            return {"total_count": len(self.checks), "check_runs": self.checks}
        raise AssertionError(f"unexpected GET {path}")

    def put(self, path, payload):
        self.calls.append(("PUT", path, payload))
        return self.merge


POLICY = RepositoryPolicy("runner", "FleetWorkAI/agent-runner", ("CI", "Security"))


class MergeGateTests(unittest.TestCase):
    def test_exact_green_head_is_squash_merged(self):
        github = FakeGithub()
        result = merge_pr(github, POLICY, 12)
        self.assertEqual(result["headSha"], SHA)
        self.assertIn(
            (
                "PUT",
                "/repos/FleetWorkAI/agent-runner/pulls/12/merge",
                {"sha": SHA, "merge_method": "squash"},
            ),
            github.calls,
        )

    def test_draft_is_refused_before_checks_or_merge(self):
        github = FakeGithub(pull={
            "state": "open",
            "draft": True,
            "mergeable": True,
            "base": {"ref": "main"},
            "head": {"sha": SHA},
        })
        with self.assertRaisesRegex(GateError, "ready for review"):
            merge_pr(github, POLICY, 12)
        self.assertFalse(any(call[0] == "PUT" for call in github.calls))

    def test_non_main_base_is_refused(self):
        pull = FakeGithub().pull | {"base": {"ref": "release"}}
        with self.assertRaisesRegex(GateError, "base must be main"):
            merge_pr(FakeGithub(pull=pull), POLICY, 12)

    def test_failed_check_is_refused(self):
        github = FakeGithub(checks=[check("CI"), check("Security", "failure")])
        with self.assertRaisesRegex(GateError, "Security: completed/failure"):
            merge_pr(github, POLICY, 12)
        self.assertFalse(any(call[0] == "PUT" for call in github.calls))

    def test_changed_head_cannot_be_merged_by_stale_sha(self):
        pull = FakeGithub().pull | {"head": {"sha": "not-a-full-sha"}}
        with self.assertRaisesRegex(GateError, "40-character"):
            merge_pr(FakeGithub(pull=pull), POLICY, 12)

    def test_unknown_policy_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "repos.json"
            path.write_text(json.dumps({"schemaVersion": 1, "repositories": {}}))
            with self.assertRaisesRegex(GateError, "not allowlisted"):
                load_policy(path, "unknown")


if __name__ == "__main__":
    unittest.main()

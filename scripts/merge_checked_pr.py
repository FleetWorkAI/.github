#!/usr/bin/env python3
"""Merge one exact PR head after fail-closed required-check validation."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from .deploy_coolify import GateError, JsonClient, validate_sha, verify_required_checks
except ImportError:  # Direct CLI execution puts scripts/ itself on sys.path.
    from deploy_coolify import GateError, JsonClient, validate_sha, verify_required_checks


@dataclass(frozen=True)
class RepositoryPolicy:
    name: str
    repository: str
    required_checks: tuple[str, ...]


def load_policy(config_path: Path, policy_name: str) -> RepositoryPolicy:
    try:
        config = json.loads(config_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"cannot read config {config_path}") from error
    rows = config.get("repositories")
    if config.get("schemaVersion") != 1 or not isinstance(rows, dict):
        raise GateError("unsupported repository config schema")
    row = rows.get(policy_name)
    if not isinstance(row, dict):
        raise GateError(f"repository policy {policy_name!r} is not allowlisted")
    repository = row.get("repository")
    checks = row.get("requiredChecks")
    if not isinstance(repository, str) or not re.fullmatch(
        r"(?:FleetWorkAI|charlesDabard)/[A-Za-z0-9_.-]+", repository
    ):
        raise GateError("invalid allowlisted repository")
    if not isinstance(checks, list) or not checks or any(not isinstance(item, str) for item in checks):
        raise GateError("requiredChecks must be a non-empty string list")
    if len(set(checks)) != len(checks):
        raise GateError("requiredChecks contains duplicates")
    return RepositoryPolicy(policy_name, repository, tuple(checks))


def merge_pr(github: JsonClient, policy: RepositoryPolicy, pr_number: int) -> dict[str, Any]:
    if pr_number <= 0:
        raise GateError("pull request number must be positive")
    repo_path = "/repos/" + urllib.parse.quote(policy.repository, safe="/")
    pull = github.get(f"{repo_path}/pulls/{pr_number}")
    if not isinstance(pull, dict):
        raise GateError("GitHub returned an invalid pull request")
    if pull.get("state") != "open" or pull.get("draft") is True:
        raise GateError("pull request must be open and ready for review")
    if pull.get("base", {}).get("ref") != "main":
        raise GateError("pull request base must be main")
    head_sha = validate_sha(str(pull.get("head", {}).get("sha", "")))
    if pull.get("mergeable") is not True:
        raise GateError("pull request is not currently mergeable")
    verify_required_checks(github, policy.repository, head_sha, policy.required_checks)
    result = github.put(
        f"{repo_path}/pulls/{pr_number}/merge",
        {"sha": head_sha, "merge_method": "squash"},
    )
    if not isinstance(result, dict) or result.get("merged") is not True:
        raise GateError("GitHub refused the exact-head merge")
    merge_sha = validate_sha(str(result.get("sha", "")))
    return {
        "status": "merged",
        "repository": policy.repository,
        "pullRequest": pr_number,
        "headSha": head_sha,
        "mergeSha": merge_sha,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr", type=int, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        policy = load_policy(args.config, args.repository)
        token = os.environ.get("FLEETWORK_GITHUB_WRITE_TOKEN", "")
        if not token:
            raise GateError("FLEETWORK_GITHUB_WRITE_TOKEN is required")
        github = JsonClient("https://api.github.com", token, "fleetwork-merge-gate/1")
        result = merge_pr(github, policy, args.pr)
    except GateError as error:
        print(f"merge gate refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

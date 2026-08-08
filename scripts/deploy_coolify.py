#!/usr/bin/env python3
"""Fail-closed deployment gate shared by FleetWork production services."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SUCCESS = "success"
TERMINAL_FAILURES = {"cancelled", "error", "failed"}

# Horodatages que Coolify est susceptible d'avancer quand un conteneur revient
# en ligne, du plus fiable au moins fiable.
#
# `last_restart_at` vaut toujours `null` sur l'instance LanaCool. Un contrôle
# fondé sur lui seul refusait donc TOUT déploiement réel, y compris ceux qui
# avaient parfaitement abouti : mesuré le 2026-08-07 sur un déploiement du
# runner terminé, conteneur sain, journaux frais, refusé par ce seul contrôle.
# Le test qui le couvrait passait parce que sa donnée d'exemple renseignait un
# champ que l'API ne renseigne jamais.
#
# `last_online_at` est celui que Coolify avance réellement, et il dit
# exactement ce qu'on cherche à prouver : le conteneur est revenu en ligne.
RESTART_MARKER_FIELDS = ("last_online_at", "last_restart_at")


class GateError(RuntimeError):
    """A validation or deployment invariant failed."""


class JsonClient:
    def __init__(self, base_url: str, token: str, user_agent: str):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.user_agent = user_agent

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        accept: str = "application/json",
    ) -> Any:
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            method=method,
            headers={
                "Accept": accept,
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": self.user_agent,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            error.read()
            raise GateError(f"{method} {path} returned HTTP {error.code}") from error
        except urllib.error.URLError as error:
            raise GateError(f"{method} {path} is unavailable") from error
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise GateError(f"{method} {path} returned invalid JSON") from error

    def get(self, path: str, accept: str = "application/json") -> Any:
        return self.request("GET", path, accept=accept)

    def patch(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("PATCH", path, payload=payload)

    def put(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("PUT", path, payload=payload)


@dataclass(frozen=True)
class Target:
    name: str
    uuid: str
    boot_marker: str


@dataclass(frozen=True)
class Service:
    name: str
    repository: str
    required_checks: tuple[str, ...]
    targets: tuple[Target, ...]
    # Services qui doivent deja tourner au sommet de leur `main` avant que
    # celui-ci parte. Voir `verify_prerequisites`.
    requires: tuple[str, ...] = ()


def load_service(config_path: Path, service_name: str) -> Service:
    try:
        config = json.loads(config_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"cannot read config {config_path}") from error
    if config.get("schemaVersion") != 1 or not isinstance(config.get("services"), dict):
        raise GateError("unsupported deployment config schema")
    raw = config["services"].get(service_name)
    if not isinstance(raw, dict):
        raise GateError(f"service {service_name!r} is not allowlisted")
    repository = raw.get("repository")
    checks = raw.get("requiredChecks")
    target_rows = raw.get("targets")
    if not isinstance(repository, str) or not re.fullmatch(r"FleetWorkAI/[A-Za-z0-9_.-]+", repository):
        raise GateError("invalid allowlisted repository")
    if not isinstance(checks, list) or not checks or any(not isinstance(item, str) for item in checks):
        raise GateError("requiredChecks must be a non-empty string list")
    if len(set(checks)) != len(checks):
        raise GateError("requiredChecks contains duplicates")
    if not isinstance(target_rows, list) or not target_rows:
        raise GateError("targets must be a non-empty list")
    targets: list[Target] = []
    seen_uuids: set[str] = set()
    for row in target_rows:
        if not isinstance(row, dict):
            raise GateError("invalid target")
        name, uuid, marker = row.get("name"), row.get("uuid"), row.get("bootMarker")
        if not all(isinstance(item, str) and item for item in (name, uuid, marker)):
            raise GateError("target name, uuid and bootMarker are required")
        if uuid in seen_uuids:
            raise GateError("a Coolify UUID appears more than once")
        try:
            re.compile(marker)
        except re.error as error:
            raise GateError(f"invalid boot marker for {name}") from error
        seen_uuids.add(uuid)
        targets.append(Target(name=name, uuid=uuid, boot_marker=marker))
    requires = raw.get("requires", [])
    if not isinstance(requires, list) or any(not isinstance(item, str) for item in requires):
        raise GateError("requires must be a list of service names")
    if len(set(requires)) != len(requires):
        raise GateError("requires contains duplicates")
    for name in requires:
        if name == service_name:
            raise GateError(f"service {service_name!r} cannot require itself")
        if name not in config["services"]:
            raise GateError(f"unknown prerequisite {name!r} for {service_name!r}")
    return Service(
        name=service_name,
        repository=repository,
        required_checks=tuple(checks),
        targets=tuple(targets),
        requires=tuple(requires),
    )


def validate_sha(sha: str) -> str:
    normalized = sha.lower()
    if not SHA_RE.fullmatch(normalized):
        raise GateError("sha must be a full 40-character Git commit")
    return normalized


def latest_required_checks(check_runs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for run in check_runs:
        if run.get("head_sha") is None or run.get("app", {}).get("slug") != "github-actions":
            continue
        name = run.get("name")
        if not isinstance(name, str):
            continue
        current = latest.get(name)
        if current is None or int(run.get("id", 0)) > int(current.get("id", 0)):
            latest[name] = run
    return latest


def verify_required_checks(
    github: JsonClient,
    repository: str,
    sha: str,
    required_checks: tuple[str, ...],
) -> None:
    repo_path = "/repos/" + urllib.parse.quote(repository, safe="/")
    checks = github.get(
        f"{repo_path}/commits/{sha}/check-runs?filter=latest&per_page=100",
        accept="application/vnd.github+json",
    )
    if not isinstance(checks, dict) or not isinstance(checks.get("check_runs"), list):
        raise GateError("GitHub returned an invalid checks response")
    if int(checks.get("total_count", 0)) > len(checks["check_runs"]):
        raise GateError("more than 100 checks found; refusing an incomplete evaluation")
    latest = latest_required_checks(checks["check_runs"])
    problems: list[str] = []
    for name in required_checks:
        run = latest.get(name)
        if run is None:
            problems.append(f"{name}: missing")
        elif run.get("head_sha", "").lower() != sha:
            problems.append(f"{name}: wrong sha")
        elif run.get("status") != "completed" or run.get("conclusion") != SUCCESS:
            problems.append(f"{name}: {run.get('status')}/{run.get('conclusion')}")
    if problems:
        raise GateError("required checks are not green: " + ", ".join(problems))


def verify_github(github: JsonClient, service: Service, sha: str) -> None:
    repo_path = "/repos/" + urllib.parse.quote(service.repository, safe="/")
    main = github.get(f"{repo_path}/commits/main")
    if not isinstance(main, dict) or str(main.get("sha", "")).lower() != sha:
        raise GateError(f"{sha[:8]} is not the current main of {service.repository}")
    verify_required_checks(github, service.repository, sha, service.required_checks)


def verify_prerequisites(
    config_path: Path,
    coolify: JsonClient,
    github: JsonClient,
    service: Service,
) -> None:
    """Refuse de deployer un service dont un prerequis est en retard.

    POURQUOI CETTE GARDE EXISTE
    Le coordinateur ecrit `effort_tier` et `model_variant` dans le snapshot
    durable ; le runner porte la fonction SQL qui decide si ce snapshot est
    normalise. Deployer le coordinateur avant le runner ne perd pas un champ :
    `job_snapshot_is_normalized` rend `false` et `admit_run` refuse alors
    100 % des admissions, de toutes les societes, chat et Kanban confondus.

    Jusqu'au 2026-08-08 cet ordre n'existait que dans un plan. Le script prend
    `--service`, un seul a la fois, donc rien n'empechait de le prendre a
    l'envers : se tromper etait un clic, pas une erreur detectee.

    LA REGLE, ET SON PRIX
    Un prerequis doit tourner au SOMMET de son propre `main`. La regle est plus
    stricte que « le prerequis porte la migration dont j'ai besoin », qu'aucune
    machine ne sait evaluer. Consequence assumee : un commit sans rapport pousse
    sur le depot du prerequis bloque ce deploiement jusqu'a ce que le prerequis
    parte aussi. C'est le bon sens de l'echec · deployer le runner d'abord est
    precisement ce qu'on veut, et l'inverse arrete la production.
    """
    for name in service.requires:
        prerequis = load_service(config_path, name)
        repo_path = "/repos/" + urllib.parse.quote(prerequis.repository, safe="/")
        main = github.get(f"{repo_path}/commits/main")
        if not isinstance(main, dict) or not isinstance(main.get("sha"), str):
            raise GateError(f"cannot read main of {prerequis.repository}")
        attendu = str(main["sha"]).lower()
        for target in prerequis.targets:
            application = coolify.get(f"/applications/{target.uuid}")
            if not isinstance(application, dict):
                raise GateError(f"invalid Coolify application {target.name}")
            deploye = str(application.get("git_commit_sha", "")).lower()
            if deploye != attendu:
                raise GateError(
                    f"prerequisite {name} is behind: {target.name} runs "
                    f"{deploye[:8] or 'nothing'} but {prerequis.repository} main is "
                    f"{attendu[:8]}. Deploy {name} first: taking this order backwards "
                    f"makes admit_run refuse every run."
                )


def env_keys(rows: Any) -> list[tuple[str, bool]]:
    if isinstance(rows, dict):
        rows = rows.get("data", [])
    if not isinstance(rows, list):
        raise GateError("Coolify returned invalid environment variables")
    keys: list[tuple[str, bool]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = row.get("key") or row.get("name")
        if isinstance(key, str) and key:
            keys.append((key, bool(row.get("is_preview"))))
    return keys


def assert_no_duplicate_env(coolify: JsonClient, target: Target) -> None:
    keys = env_keys(coolify.get(f"/applications/{target.uuid}/envs"))
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    if duplicates:
        labels = [f"{key}[{'preview' if preview else 'production'}]" for key, preview in duplicates]
        raise GateError(f"{target.name} has duplicate environment keys: {', '.join(labels)}")


def preflight_target(coolify: JsonClient, service: Service, target: Target) -> dict[str, Any]:
    application = coolify.get(f"/applications/{target.uuid}")
    if not isinstance(application, dict):
        raise GateError(f"invalid Coolify application {target.name}")
    if application.get("name") != target.name:
        raise GateError(f"Coolify name mismatch for {target.name}")
    if application.get("git_repository") != service.repository:
        raise GateError(f"Coolify repository mismatch for {target.name}")
    if application.get("git_branch") != "main":
        raise GateError(f"{target.name} does not track main")
    assert_no_duplicate_env(coolify, target)
    return application


def deployment_uuid(payload: Any) -> str:
    if isinstance(payload, dict):
        direct = payload.get("deployment_uuid")
        if isinstance(direct, str) and direct:
            return direct
        deployments = payload.get("deployments")
        if isinstance(deployments, list) and deployments:
            found = deployments[0].get("deployment_uuid")
            if isinstance(found, str) and found:
                return found
    raise GateError("Coolify did not return a deployment UUID")


def wait_for_terminal(
    coolify: JsonClient,
    deploy_uuid: str,
    timeout_seconds: int,
    poll_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_status = None
    while time.monotonic() < deadline:
        state = coolify.get(f"/deployments/{deploy_uuid}")
        if not isinstance(state, dict):
            raise GateError("Coolify returned an invalid deployment state")
        status = state.get("status")
        if status != last_status:
            print(f"deployment {deploy_uuid}: {status}", flush=True)
            last_status = status
        if status == "finished":
            return state
        if status in TERMINAL_FAILURES:
            raise GateError(f"deployment {deploy_uuid} ended with {status}")
        time.sleep(poll_seconds)
    raise GateError(f"deployment {deploy_uuid} did not finish before timeout")


def restart_marker(app: dict[str, Any]) -> tuple[str, str] | None:
    """Le premier horodatage de redémarrage réellement renseigné, avec son nom.

    Renvoie le nom du champ en plus de sa valeur : sans lui, une valeur lue
    dans un champ avant le déploiement et dans un autre après passerait pour
    un changement, alors qu'elle ne prouve rien.
    """
    for field in RESTART_MARKER_FIELDS:
        value = app.get(field)
        if isinstance(value, str) and value.strip():
            return field, value
    return None


def deploy_target(
    coolify: JsonClient,
    service: Service,
    target: Target,
    sha: str,
    timeout_seconds: int,
    poll_seconds: int,
) -> str:
    before = preflight_target(coolify, service, target)
    previous_restart = restart_marker(before)
    coolify.patch(f"/applications/{target.uuid}", {"git_commit_sha": sha})
    pinned = coolify.get(f"/applications/{target.uuid}")
    if not isinstance(pinned, dict) or str(pinned.get("git_commit_sha", "")).lower() != sha:
        raise GateError(f"Coolify did not retain the exact SHA for {target.name}")
    triggered = coolify.get(f"/deploy?uuid={urllib.parse.quote(target.uuid)}&force=false")
    deploy_uuid = deployment_uuid(triggered)
    state = wait_for_terminal(coolify, deploy_uuid, timeout_seconds, poll_seconds)
    deployed_sha = state.get("commit") or state.get("git_commit_sha")
    if not isinstance(deployed_sha, str) or deployed_sha.lower() != sha:
        raise GateError(f"deployment {deploy_uuid} did not prove commit {sha[:8]}")
    after = coolify.get(f"/applications/{target.uuid}")
    if not isinstance(after, dict) or str(after.get("git_commit_sha", "")).lower() != sha:
        raise GateError(f"{target.name} no longer pins the approved SHA")
    if "running" not in str(after.get("status", "")):
        raise GateError(f"{target.name} is not running after deployment")
    current_restart = restart_marker(after)
    if current_restart is None:
        raise GateError(f"{target.name} exposes no restart timestamp to compare")
    if previous_restart is not None and previous_restart[0] != current_restart[0]:
        raise GateError(f"{target.name} switched restart timestamp field mid-deployment")
    if current_restart == previous_restart:
        raise GateError(f"{target.name} has no fresh restart marker")
    logs_payload = coolify.get(f"/applications/{target.uuid}/logs?lines=200")
    logs = logs_payload.get("logs", "") if isinstance(logs_payload, dict) else str(logs_payload)
    if re.search(target.boot_marker, logs, flags=re.IGNORECASE) is None:
        raise GateError(f"{target.name} fresh logs lack its boot marker")
    return deploy_uuid


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=2400)
    parser.add_argument("--poll-seconds", type=int, default=10)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    service = load_service(args.config, args.service)
    sha = validate_sha(args.sha)
    github_token = os.environ.get("FLEETWORK_GITHUB_READ_TOKEN", "")
    if not github_token:
        raise GateError("FLEETWORK_GITHUB_READ_TOKEN is required")
    github = JsonClient("https://api.github.com", github_token, "fleetwork-deploy-gate/1")
    verify_github(github, service, sha)
    coolify_url = os.environ.get("COOLIFY_URL", "").rstrip("/")
    coolify_token = os.environ.get("COOLIFY_API_TOKEN", "")
    if not coolify_url.startswith("https://") or not coolify_token:
        raise GateError("COOLIFY_URL and COOLIFY_API_TOKEN are required")
    coolify = JsonClient(f"{coolify_url}/api/v1", coolify_token, "fleetwork-deploy-gate/1")
    # Avant le vol a blanc comme avant le vrai deploiement : un « validated »
    # rendu sur un ordre faux serait un feu vert pour la panne.
    verify_prerequisites(args.config, coolify, github, service)
    if args.dry_run:
        for target in service.targets:
            preflight_target(coolify, service, target)
        return {
            "status": "validated",
            "service": service.name,
            "sha": sha,
            "targets": [target.name for target in service.targets],
        }
    deployed: list[dict[str, str]] = []
    for target in service.targets:
        deploy_uuid = deploy_target(
            coolify,
            service,
            target,
            sha,
            args.timeout_seconds,
            args.poll_seconds,
        )
        deployed.append({"target": target.name, "deployment": deploy_uuid})
    return {"status": "finished", "service": service.name, "sha": sha, "deployed": deployed}


def main() -> int:
    try:
        result = run(build_parser().parse_args())
    except GateError as error:
        print(f"deployment gate refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

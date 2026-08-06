#!/usr/bin/env python3
"""Reconcile least-privilege LiteLLM workload keys without printing secrets."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


KEY_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
ALIAS_RE = re.compile(r"^fleet-[a-z0-9-]+$")
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")
REPOSITORY_RE = re.compile(r"^FleetWorkAI/[A-Za-z0-9_.-]+$")
MANAGED_FIELDS = (
    "key_alias",
    "models",
    "allowed_routes",
    "permissions",
    "rpm_limit",
    "tpm_limit",
    "max_parallel_requests",
    "max_budget",
    "budget_duration",
    "metadata",
    "blocked",
)


class ReconcileError(RuntimeError):
    """A desired-state, API, or secret-sink invariant failed."""


class JsonClient:
    def __init__(self, base_url: str, token: str, user_agent: str):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.user_agent = user_agent

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": self.user_agent,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            error.read()
            raise ReconcileError(f"{method} {path.split('?')[0]} returned HTTP {error.code}") from error
        except urllib.error.URLError as error:
            raise ReconcileError(f"{method} {path.split('?')[0]} is unavailable") from error
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise ReconcileError(f"{method} {path.split('?')[0]} returned invalid JSON") from error

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("POST", path, payload)

    def patch(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("PATCH", path, payload)


class SmokeHttpClient:
    """Status-only client. Response bodies and authorization values never escape."""

    def request(
        self,
        base_url: str,
        key: str,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> int:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        request = urllib.request.Request(
            f"{base_url.rstrip('/')}{path}",
            data=body,
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "User-Agent": "fleetwork-litellm-key-smoke/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                return response.status
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            return status
        except urllib.error.URLError as error:
            raise ReconcileError(f"{method} {path.split('?')[0]} smoke is unavailable") from error


@dataclass(frozen=True)
class Sink:
    type: str
    key: str
    application_uuid: str | None = None
    is_preview: bool = False
    repository: str | None = None
    environment: str | None = None
    fingerprint_key: str | None = None


@dataclass(frozen=True)
class Workload:
    id: str
    key_alias: str
    legacy_aliases: tuple[str, ...]
    desired: dict[str, Any]
    sinks: tuple[Sink, ...]

    @property
    def aliases(self) -> frozenset[str]:
        return frozenset((self.key_alias, *self.legacy_aliases))


@dataclass(frozen=True)
class CurrentKey:
    identifier: str
    data: dict[str, Any]


@dataclass
class AppliedChange:
    workload: Workload
    action: str
    identifier: str
    previous: dict[str, Any] | None = None


def _required_string(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise ReconcileError(f"{key} must be a non-empty string")
    return value


def _string_list(row: dict[str, Any], key: str) -> list[str]:
    value = row.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ReconcileError(f"{key} must be a string list")
    if len(set(value)) != len(value):
        raise ReconcileError(f"{key} contains duplicates")
    return value


def _load_sink(row: Any) -> Sink:
    if not isinstance(row, dict):
        raise ReconcileError("each workload sink must be an object")
    sink_type = _required_string(row, "type")
    key = _required_string(row, "key")
    if not ENV_KEY_RE.fullmatch(key):
        raise ReconcileError(f"invalid secret sink key {key!r}")
    if sink_type == "coolify_env":
        uuid = _required_string(row, "applicationUuid")
        if row.get("isPreview", False) not in (True, False):
            raise ReconcileError("Coolify isPreview must be boolean")
        return Sink(sink_type, key, application_uuid=uuid, is_preview=bool(row.get("isPreview")))
    if sink_type == "github_environment_secret":
        repository = _required_string(row, "repository")
        environment = _required_string(row, "environment")
        fingerprint_key = _required_string(row, "fingerprintKey")
        if not REPOSITORY_RE.fullmatch(repository):
            raise ReconcileError("invalid GitHub secret repository")
        if not ENV_KEY_RE.fullmatch(fingerprint_key) or fingerprint_key == key:
            raise ReconcileError("invalid GitHub fingerprint variable")
        return Sink(
            sink_type,
            key,
            repository=repository,
            environment=environment,
            fingerprint_key=fingerprint_key,
        )
    raise ReconcileError(f"unsupported secret sink type {sink_type!r}")


def load_config(path: Path, catalog_path: Path) -> tuple[str, tuple[Workload, ...]]:
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ReconcileError(f"cannot read workload key config {path}") from error
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise ReconcileError("unsupported workload key config schema")
    catalog_version = _required_string(raw, "catalogVersion")
    if raw.get("litellmVersion") != "1.83.10":
        raise ReconcileError("workload key contract must target deployed LiteLLM 1.83.10")
    rows = raw.get("workloads")
    if not isinstance(rows, list) or not rows:
        raise ReconcileError("workloads must be a non-empty list")

    workloads: list[Workload] = []
    aliases: set[str] = set()
    ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ReconcileError("each workload must be an object")
        workload_id = _required_string(row, "id")
        alias = _required_string(row, "keyAlias")
        legacy = _string_list(row, "legacyAliases")
        models = _string_list(row, "models")
        routes = _string_list(row, "allowedRoutes")
        permissions = row.get("permissions")
        limits = row.get("limits")
        if not ALIAS_RE.fullmatch(alias) or any(not ALIAS_RE.fullmatch(item) for item in legacy):
            raise ReconcileError(f"workload {workload_id} has an invalid key alias")
        if not routes:
            raise ReconcileError(f"workload {workload_id} must be fail-closed to explicit routes")
        if not isinstance(permissions, dict) or any(value is not True for value in permissions.values()):
            raise ReconcileError(f"workload {workload_id} permissions must contain only true grants")
        if not isinstance(limits, dict):
            raise ReconcileError(f"workload {workload_id} limits must be an object")
        for field in ("rpm", "tpm", "maxParallelRequests"):
            if field in limits and (not isinstance(limits[field], int) or limits[field] <= 0):
                raise ReconcileError(f"workload {workload_id} limit {field} must be positive")
        if ("maxBudgetUsd" in limits) != ("budgetDuration" in limits):
            raise ReconcileError(f"workload {workload_id} budget limit and duration must be paired")
        if "maxBudgetUsd" in limits and (
            not isinstance(limits["maxBudgetUsd"], (int, float)) or limits["maxBudgetUsd"] <= 0
        ):
            raise ReconcileError(f"workload {workload_id} maxBudgetUsd must be positive")
        sinks = tuple(_load_sink(item) for item in row.get("sinks", []))
        if not sinks:
            raise ReconcileError(f"workload {workload_id} must declare at least one secret sink")
        desired = {
            "key_alias": alias,
            "models": sorted(models),
            "allowed_routes": sorted(routes),
            "permissions": permissions,
            "rpm_limit": limits.get("rpm"),
            "tpm_limit": limits.get("tpm"),
            "max_parallel_requests": limits.get("maxParallelRequests"),
            "max_budget": limits.get("maxBudgetUsd"),
            "budget_duration": limits.get("budgetDuration"),
            "metadata": {
                "managed_by": "fleetwork",
                "workload": workload_id,
                "catalog_version": catalog_version,
            },
            "blocked": False,
        }
        all_aliases = (alias, *legacy)
        if workload_id in ids or any(item in aliases for item in all_aliases):
            raise ReconcileError("workload ids and current/legacy aliases must be globally unique")
        ids.add(workload_id)
        aliases.update(all_aliases)
        workloads.append(Workload(workload_id, alias, tuple(legacy), desired, sinks))
    result = tuple(workloads)
    validate_against_catalog(catalog_path, catalog_version, result)
    return catalog_version, result


def validate_against_catalog(
    catalog_path: Path,
    catalog_version: str,
    workloads: tuple[Workload, ...],
) -> None:
    try:
        catalog = json.loads(catalog_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ReconcileError(f"cannot read model catalog {catalog_path}") from error
    if not isinstance(catalog, dict) or catalog.get("catalogVersion") != catalog_version:
        raise ReconcileError("workload keys and model catalog versions do not match")
    model_rows = catalog.get("models")
    internal_rows = catalog.get("internalModels")
    if not isinstance(model_rows, list) or not isinstance(internal_rows, list):
        raise ReconcileError("model catalog has an invalid shape")
    # `selectable` gouverne le sélecteur de l'interface, pas l'exécution. Une clé
    # de workload doit couvrir tout ce qui peut encore tourner, alias dépréciés
    # compris, sinon la dépréciation coupe les agents déjà configurés au lieu de
    # les laisser drainer. Seul `retired` sort du périmètre exécutable.
    chat = sorted(
        row.get("alias")
        for row in model_rows
        if isinstance(row, dict)
        and isinstance(row.get("lifecycle"), dict)
        and row["lifecycle"].get("status") in ("active", "deprecated")
        and isinstance(row.get("alias"), str)
    )
    embeddings = sorted(
        row.get("alias")
        for row in internal_rows
        if isinstance(row, dict)
        and row.get("purpose") == "embedding"
        and isinstance(row.get("alias"), str)
    )
    if len(chat) != 6 or embeddings != ["text-embedding-3-small"]:
        raise ReconcileError("model catalog must expose six executable chat aliases and one embedding route")
    by_id = {workload.id: workload for workload in workloads}
    if set(by_id) != {"runner", "coordinator", "catalog-probe", "spend-reader"}:
        raise ReconcileError("workload key config must define the four governed workloads")
    if by_id["runner"].desired["models"] != sorted((*chat, *embeddings)):
        raise ReconcileError("runner key models do not match the governed catalog")
    if by_id["coordinator"].desired["models"] != ["gpt-5-nano"]:
        raise ReconcileError("coordinator key must be limited to gpt-5-nano")
    if by_id["catalog-probe"].desired["models"] != chat:
        raise ReconcileError("catalog probe key models do not match selectable chat aliases")
    if by_id["spend-reader"].desired["models"]:
        raise ReconcileError("spend reader key must not grant model access")
    if by_id["spend-reader"].desired["permissions"]:
        raise ReconcileError("spend reader must not require Enterprise-only permissions")
    if by_id["spend-reader"].desired["allowed_routes"] != ["/spend/logs"]:
        raise ReconcileError("spend reader must be limited to /spend/logs")


def _list_rows(payload: Any) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
        raise ReconcileError("LiteLLM /key/list returned an invalid shape")
    rows = [row for row in payload["keys"] if isinstance(row, dict)]
    if len(rows) != len(payload["keys"]):
        raise ReconcileError("LiteLLM /key/list returned a non-object key")
    pages = payload.get("total_pages", 1)
    if not isinstance(pages, int) or pages < 1:
        raise ReconcileError("LiteLLM /key/list returned an invalid page count")
    return rows, pages


def list_all_keys(client: JsonClient) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    page = 1
    total_pages = 1
    while page <= total_pages:
        payload = client.get(f"/key/list?page={page}&size=100&return_full_object=true")
        page_rows, total_pages = _list_rows(payload)
        rows.extend(page_rows)
        if total_pages > 1000:
            raise ReconcileError("LiteLLM key pagination exceeds the safety bound")
        page += 1
    return rows


def _key_identifier(row: dict[str, Any]) -> str:
    for field in ("token", "key_hash", "key"):
        value = row.get(field)
        if isinstance(value, str) and KEY_HASH_RE.fullmatch(value.lower()):
            return value.lower()
    raise ReconcileError("LiteLLM key row lacks an immutable hashed identifier")


def index_managed_keys(rows: list[dict[str, Any]], workloads: tuple[Workload, ...]) -> dict[str, CurrentKey]:
    indexed: dict[str, CurrentKey] = {}
    workload_ids = {workload.id for workload in workloads}
    for row in rows:
        metadata = row.get("metadata")
        if (
            isinstance(metadata, dict)
            and metadata.get("managed_by") == "fleetwork"
            and metadata.get("workload") not in workload_ids
        ):
            raise ReconcileError("LiteLLM contains a Fleetwork-managed key for an unknown workload")
    for workload in workloads:
        matches = []
        for row in rows:
            metadata = row.get("metadata")
            metadata_match = (
                isinstance(metadata, dict)
                and metadata.get("managed_by") == "fleetwork"
                and metadata.get("workload") == workload.id
                and metadata.get("key_role", "current") == "current"
            )
            if row.get("key_alias") in workload.aliases or metadata_match:
                matches.append(row)
        if len(matches) > 1:
            raise ReconcileError(f"workload {workload.id} has duplicate managed keys")
        if matches:
            indexed[workload.id] = CurrentKey(_key_identifier(matches[0]), matches[0])
    identifiers = [current.identifier for current in indexed.values()]
    if len(identifiers) != len(set(identifiers)):
        raise ReconcileError("one LiteLLM key is assigned to multiple workloads")
    return indexed


def _normalized(field: str, value: Any) -> Any:
    if field in ("models", "allowed_routes"):
        return sorted(value) if isinstance(value, list) else value
    if field == "metadata":
        return value if isinstance(value, dict) else {}
    return value


def drift_fields(current: dict[str, Any], desired: dict[str, Any]) -> list[str]:
    drift: list[str] = []
    for field in MANAGED_FIELDS:
        expected = desired[field]
        actual = current.get(field)
        if field == "metadata":
            if actual != expected:
                drift.append(field)
        elif _normalized(field, actual) != _normalized(field, expected):
            drift.append(field)
    return drift


def desired_update(identifier: str, desired: dict[str, Any]) -> dict[str, Any]:
    return {"key": identifier, **desired}


def snapshot_for_rollback(current: CurrentKey) -> dict[str, Any]:
    snapshot = {"key": current.identifier}
    for field in MANAGED_FIELDS:
        snapshot[field] = current.data.get(field)
    return snapshot


def _find_by_alias(client: JsonClient, workload: Workload) -> CurrentKey | None:
    matches = []
    for row in list_all_keys(client):
        metadata = row.get("metadata")
        metadata_match = (
            isinstance(metadata, dict)
            and metadata.get("managed_by") == "fleetwork"
            and metadata.get("workload") == workload.id
            and metadata.get("key_role", "current") == "current"
        )
        if row.get("key_alias") in workload.aliases or metadata_match:
            matches.append(row)
    if len(matches) > 1:
        raise ReconcileError(f"workload {workload.id} has duplicate managed keys")
    if not matches:
        return None
    return CurrentKey(_key_identifier(matches[0]), matches[0])


def _created_secret(payload: Any) -> str:
    if not isinstance(payload, dict):
        raise ReconcileError("LiteLLM /key/generate returned an invalid shape")
    secret = payload.get("key")
    if not isinstance(secret, str) or len(secret) < 20:
        raise ReconcileError("LiteLLM /key/generate did not return a usable key")
    return secret


def create_key_or_revoke_ambiguous(client: JsonClient, workload: Workload) -> tuple[str, str]:
    try:
        payload = client.post("/key/generate", workload.desired)
        secret = _created_secret(payload)
        return secret, hashlib.sha256(secret.encode()).hexdigest()
    except ReconcileError as original:
        try:
            recovered = _find_by_alias(client, workload)
            if recovered is not None:
                client.post("/key/delete", {"keys": [recovered.identifier]})
        except Exception as cleanup_error:
            raise ReconcileError(
                f"workload {workload.id} key creation is ambiguous and cleanup could not be proven"
            ) from cleanup_error
        raise original


def rotation_candidates(
    rows: list[dict[str, Any]], workload: Workload
) -> list[CurrentKey]:
    candidates: list[CurrentKey] = []
    for row in rows:
        metadata = row.get("metadata")
        if (
            isinstance(metadata, dict)
            and metadata.get("managed_by") == "fleetwork"
            and metadata.get("workload") == workload.id
            and metadata.get("key_role") == "rotation_candidate"
        ):
            candidates.append(CurrentKey(_key_identifier(row), row))
    identifiers = [candidate.identifier for candidate in candidates]
    if len(identifiers) != len(set(identifiers)):
        raise ReconcileError(f"workload {workload.id} has duplicate rotation candidates")
    return candidates


def create_replacement_or_revoke_ambiguous(
    client: JsonClient, workload: Workload, previous_identifiers: set[str]
) -> tuple[str, CurrentKey, dict[str, Any]]:
    suffix = secrets.token_hex(4)
    candidate_desired = {
        **workload.desired,
        "key_alias": f"{workload.key_alias}-next-{suffix}",
        "metadata": {
            **workload.desired["metadata"],
            "key_role": "rotation_candidate",
        },
    }
    try:
        payload = client.post("/key/generate", candidate_desired)
        secret = _created_secret(payload)
        identifier = hashlib.sha256(secret.encode()).hexdigest()
        return secret, CurrentKey(identifier, candidate_desired), candidate_desired
    except ReconcileError as original:
        try:
            candidates = []
            for row in list_all_keys(client):
                if row.get("key_alias") == candidate_desired["key_alias"]:
                    identifier = _key_identifier(row)
                    if identifier not in previous_identifiers:
                        candidates.append(identifier)
            if len(candidates) == 1:
                client.post("/key/delete", {"keys": candidates})
            elif candidates:
                raise ReconcileError("replacement candidates are ambiguous")
        except Exception as cleanup_error:
            raise ReconcileError(
                f"workload {workload.id} replacement creation is ambiguous and cleanup could not be proven"
            ) from cleanup_error
        raise original


def _coolify_env_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        payload = payload.get("data")
    if not isinstance(payload, list) or any(not isinstance(row, dict) for row in payload):
        raise ReconcileError("Coolify returned invalid environment variables")
    return payload


def write_coolify_secret(client: JsonClient, sink: Sink, secret: str) -> None:
    path = f"/applications/{sink.application_uuid}/envs"
    rows = _coolify_env_rows(client.get(path))
    matches = [
        row
        for row in rows
        if (row.get("key") or row.get("name")) == sink.key
        and bool(row.get("is_preview")) == sink.is_preview
    ]
    if len(matches) > 1:
        raise ReconcileError(f"Coolify has duplicate {sink.key} rows in the requested scope")
    payload = {"key": sink.key, "value": secret, "is_preview": sink.is_preview}
    if matches:
        client.patch(path, payload)
    else:
        client.post(path, payload)
    reread = _coolify_env_rows(client.get(path))
    verified = [
        row
        for row in reread
        if (row.get("key") or row.get("name")) == sink.key
        and bool(row.get("is_preview")) == sink.is_preview
    ]
    if len(verified) != 1 or not isinstance(verified[0].get("value"), str):
        raise ReconcileError(f"Coolify did not retain one exact {sink.key} row")
    if not hmac.compare_digest(verified[0]["value"], secret):
        raise ReconcileError(f"Coolify did not retain the exact {sink.key} secret")


def write_github_secret(sink: Sink, secret: str, github_token: str) -> None:
    environment = {**os.environ, "GH_TOKEN": github_token}
    command = [
        "gh",
        "secret",
        "set",
        sink.key,
        "--env",
        str(sink.environment),
        "--repo",
        str(sink.repository),
    ]
    try:
        subprocess.run(
            command,
            input=secret.encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=True,
            timeout=30,
        )
        fingerprint = hashlib.sha256(secret.encode()).hexdigest()
        subprocess.run(
            [
                "gh",
                "variable",
                "set",
                str(sink.fingerprint_key),
                "--env",
                str(sink.environment),
                "--repo",
                str(sink.repository),
                "--body",
                fingerprint,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=True,
            timeout=30,
        )
        secrets, fingerprints = read_github_sink(sink, github_token)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise ReconcileError(f"GitHub could not store environment secret {sink.key}") from error
    fingerprint_row = fingerprints.get(str(sink.fingerprint_key), {})
    secret_updated = secrets.get(sink.key, "")
    fingerprint_updated = fingerprint_row.get("updated_at", "")
    if (
        not secret_updated
        or not fingerprint_updated
        or secret_updated > fingerprint_updated
        or not hmac.compare_digest(fingerprint_row.get("value", ""), fingerprint)
    ):
        raise ReconcileError(f"GitHub could not verify environment secret {sink.key}")


def read_github_sink(
    sink: Sink, github_token: str
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    environment = {**os.environ, "GH_TOKEN": github_token}
    try:
        listed = subprocess.run(
            [
                "gh",
                "secret",
                "list",
                "--env",
                str(sink.environment),
                "--repo",
                str(sink.repository),
                "--json",
                "name,updatedAt",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=True,
            timeout=30,
        )
        secrets = {
            row.get("name"): row.get("updatedAt")
            for row in json.loads(listed.stdout)
            if isinstance(row, dict)
            and isinstance(row.get("name"), str)
            and isinstance(row.get("updatedAt"), str)
        }
        variables = subprocess.run(
            [
                "gh",
                "variable",
                "list",
                "--env",
                str(sink.environment),
                "--repo",
                str(sink.repository),
                "--json",
                "name,value,updatedAt",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=True,
            timeout=30,
        )
        fingerprints = {
            row.get("name"): {
                "value": row.get("value"),
                "updated_at": row.get("updatedAt"),
            }
            for row in json.loads(variables.stdout)
            if isinstance(row, dict)
            and isinstance(row.get("name"), str)
            and isinstance(row.get("value"), str)
            and isinstance(row.get("updatedAt"), str)
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise ReconcileError(f"GitHub could not inspect environment secret {sink.key}") from error
    return secrets, fingerprints


def inspect_secret_sinks(
    workloads: tuple[Workload, ...],
    indexed: dict[str, CurrentKey],
    coolify: JsonClient | None,
    github_token: str,
) -> dict[str, list[str]]:
    drift: dict[str, list[str]] = {}
    for workload in workloads:
        current = indexed.get(workload.id)
        for sink in workload.sinks:
            if sink.type == "coolify_env":
                if coolify is None:
                    raise ReconcileError("Coolify credentials are required by a workload secret sink")
                path = f"/applications/{sink.application_uuid}/envs"
                rows = _coolify_env_rows(coolify.get(path))
                matches = [
                    row
                    for row in rows
                    if (row.get("key") or row.get("name")) == sink.key
                    and bool(row.get("is_preview")) == sink.is_preview
                ]
                if len(matches) > 1:
                    raise ReconcileError(f"Coolify has duplicate {sink.key} rows in the requested scope")
                if current is not None:
                    value = matches[0].get("value") if len(matches) == 1 else None
                    fingerprint = (
                        hashlib.sha256(value.encode()).hexdigest()
                        if isinstance(value, str)
                        else ""
                    )
                    if not hmac.compare_digest(fingerprint, current.identifier):
                        drift.setdefault(workload.id, []).append(f"coolify:{sink.key}")
            else:
                if not github_token:
                    raise ReconcileError(
                        "FLEETWORK_GITHUB_WRITE_TOKEN is required by a GitHub secret sink"
                    )
                secrets, fingerprints = read_github_sink(sink, github_token)
                if current is not None:
                    expected = current.identifier
                    fingerprint_row = fingerprints.get(str(sink.fingerprint_key), {})
                    actual = fingerprint_row.get("value", "")
                    secret_updated = secrets.get(sink.key, "")
                    fingerprint_updated = fingerprint_row.get("updated_at", "")
                    if (
                        not secret_updated
                        or not fingerprint_updated
                        or secret_updated > fingerprint_updated
                        or not hmac.compare_digest(actual, expected)
                    ):
                        drift.setdefault(workload.id, []).append(f"github:{sink.key}")
    return drift


def publish_secret(
    sinks: tuple[Sink, ...],
    secret: str,
    coolify: JsonClient | None,
    github_token: str,
) -> None:
    for sink in sinks:
        if sink.type == "coolify_env":
            if coolify is None:
                raise ReconcileError("Coolify credentials are required by a workload secret sink")
            write_coolify_secret(coolify, sink, secret)
        else:
            if not github_token:
                raise ReconcileError("FLEETWORK_GITHUB_WRITE_TOKEN is required by a GitHub secret sink")
            write_github_secret(sink, secret, github_token)


def secret_sink_matches(
    workload: Workload,
    sink: Sink,
    candidate: CurrentKey,
    coolify: JsonClient | None,
    github_token: str,
) -> bool:
    """Inspect one sink independently so partial publication is never hidden."""
    isolated = Workload(
        workload.id,
        workload.key_alias,
        workload.legacy_aliases,
        workload.desired,
        (sink,),
    )
    return not inspect_secret_sinks(
        (isolated,),
        {workload.id: candidate},
        coolify,
        github_token,
    )


def rotate_key(
    workload: Workload,
    current: CurrentKey | None,
    litellm: JsonClient,
    coolify: JsonClient | None,
    github_token: str,
) -> str:
    rows = list_all_keys(litellm)
    pending = rotation_candidates(rows, workload)
    if len(pending) >= 5:
        raise ReconcileError(
            f"workload {workload.id} has too many pending rotation candidates; manual review required"
        )

    if current is not None and pending and not drift_fields(current.data, workload.desired):
        current_sink_drift = inspect_secret_sinks(
            (workload,), {workload.id: current}, coolify, github_token
        )
        if not current_sink_drift:
            stale = sorted(candidate.identifier for candidate in pending)
            litellm.post("/key/delete", {"keys": stale})
            remaining = rotation_candidates(list_all_keys(litellm), workload)
            if remaining:
                raise ReconcileError(
                    f"workload {workload.id} stale rotation candidate cleanup is incomplete"
                )
            return current.identifier

    published = []
    partial_or_ambiguous = []
    for candidate in pending:
        matching = 0
        uncertain = False
        for sink in workload.sinks:
            try:
                matching += int(
                    secret_sink_matches(
                        workload, sink, candidate, coolify, github_token
                    )
                )
            except ReconcileError:
                uncertain = True
        if matching == len(workload.sinks):
            published.append(candidate)
        elif matching > 0 or uncertain:
            partial_or_ambiguous.append(candidate)
    if len(published) > 1:
        raise ReconcileError(
            f"workload {workload.id} has multiple published rotation candidates"
        )
    if published:
        return complete_rotation(workload, current, published[0], pending, litellm)
    if partial_or_ambiguous:
        raise ReconcileError(
            f"workload {workload.id} has a partially published or uninspectable rotation "
            "candidate; it was kept active and requires sink recovery"
        )

    previous_identifiers = {candidate.identifier for candidate in pending}
    if current is not None:
        previous_identifiers.add(current.identifier)
    secret, provisional, candidate_desired = create_replacement_or_revoke_ambiguous(
        litellm, workload, previous_identifiers
    )
    identifier = provisional.identifier
    replacement = next(
        (CurrentKey(_key_identifier(row), row) for row in list_all_keys(litellm)
         if row.get("key_alias") == candidate_desired["key_alias"]),
        None,
    )
    if replacement is None or drift_fields(replacement.data, candidate_desired):
        litellm.post("/key/delete", {"keys": [identifier]})
        raise ReconcileError(f"workload {workload.id} replacement failed verification")

    publication_error: Exception | None = None
    for _ in range(3):
        try:
            publish_secret(workload.sinks, secret, coolify, github_token)
            publication_error = None
            break
        except Exception as error:
            publication_error = error
    if publication_error is not None:
        # Inspect every sink independently. A candidate is revocable only when
        # every Coolify sink proves it did not receive the new secret. If one
        # sink did receive it, or any sink is write-only/unavailable, keep both
        # keys active so no deployed workload is left with a dead credential.
        matching = 0
        uncertain = False
        for sink in workload.sinks:
            try:
                matching += int(
                    secret_sink_matches(
                        workload, sink, replacement, coolify, github_token
                    )
                )
            except Exception:
                uncertain = True
        if (
            matching == 0
            and not uncertain
            and all(sink.type == "coolify_env" for sink in workload.sinks)
        ):
            litellm.post("/key/delete", {"keys": [identifier]})
            raise ReconcileError(
                f"workload {workload.id} rotation did not reach Coolify; replacement revoked"
            ) from publication_error
        raise ReconcileError(
            f"workload {workload.id} rotation publication is ambiguous; the identified candidate was kept active"
        ) from publication_error

    published_drift = inspect_secret_sinks(
        (workload,), {workload.id: replacement}, coolify, github_token
    )
    if published_drift:
        raise ReconcileError(
            f"workload {workload.id} replacement fingerprint is ambiguous; the identified candidate was kept active"
        )

    return complete_rotation(workload, current, replacement, [*pending, replacement], litellm)


def complete_rotation(
    workload: Workload,
    current: CurrentKey | None,
    replacement: CurrentKey,
    candidates: list[CurrentKey],
    litellm: JsonClient,
) -> str:
    if current is not None and current.identifier != replacement.identifier:
        litellm.post("/key/delete", {"keys": [current.identifier]})
    litellm.post(
        "/key/update",
        desired_update(replacement.identifier, workload.desired),
    )
    verified = _find_by_alias(litellm, workload)
    if (
        verified is None
        or verified.identifier != replacement.identifier
        or drift_fields(verified.data, workload.desired)
    ):
        raise ReconcileError(
            f"workload {workload.id} rotation final verification failed; the published candidate remains active"
        )
    stale = sorted(
        candidate.identifier
        for candidate in candidates
        if candidate.identifier != replacement.identifier
    )
    if stale:
        litellm.post("/key/delete", {"keys": stale})
    return replacement.identifier


def _coolify_sink_secret(coolify: JsonClient | None, sink: Sink) -> str:
    if coolify is None:
        raise ReconcileError("Coolify credentials are required by workload smoke")
    rows = _coolify_env_rows(coolify.get(f"/applications/{sink.application_uuid}/envs"))
    matches = [
        row
        for row in rows
        if (row.get("key") or row.get("name")) == sink.key
        and bool(row.get("is_preview")) == sink.is_preview
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("value"), str):
        raise ReconcileError(f"Coolify smoke secret {sink.key} is missing or duplicated")
    value = matches[0]["value"]
    if not value:
        raise ReconcileError(f"Coolify smoke secret {sink.key} is empty")
    return value


def _smoke_secrets(
    workloads: tuple[Workload, ...],
    indexed: dict[str, CurrentKey],
    coolify: JsonClient | None,
    environment: dict[str, str],
) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for workload in workloads:
        current = indexed.get(workload.id)
        if current is None or drift_fields(current.data, workload.desired):
            raise ReconcileError(f"workload {workload.id} must be current before smoke")
        if workload.id == "catalog-probe":
            secret = environment.get("FLEETWORK_SMOKE_CATALOG_PROBE_KEY", "")
            if not secret:
                raise ReconcileError("catalog probe smoke secret is required")
        else:
            coolify_sinks = [sink for sink in workload.sinks if sink.type == "coolify_env"]
            if len(coolify_sinks) != 1:
                raise ReconcileError(f"workload {workload.id} must have one readable smoke sink")
            secret = _coolify_sink_secret(coolify, coolify_sinks[0])
        fingerprint = hashlib.sha256(secret.encode()).hexdigest()
        if not hmac.compare_digest(fingerprint, current.identifier):
            raise ReconcileError(f"workload {workload.id} smoke secret fingerprint does not match")
        resolved[workload.id] = secret
    return resolved


def smoke_workload_keys(
    workloads: tuple[Workload, ...],
    indexed: dict[str, CurrentKey],
    coolify: JsonClient | None,
    environment: dict[str, str],
    base_url: str,
    http: SmokeHttpClient,
) -> dict[str, Any]:
    """Exercise every grant with paired valid controls and exact HTTP 403 denials."""
    keys = _smoke_secrets(workloads, indexed, coolify, environment)
    chat = {
        "model": "gpt-5-nano",
        "messages": [{"role": "user", "content": "Resume en un mot: lancement termine."}],
        "max_completion_tokens": 16,
    }
    gpt4o_chat = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "test"}],
        "max_completion_tokens": 1,
    }
    embedding = {"model": "text-embedding-3-small", "input": ["smoke"]}
    models_path = "/v1/models"
    spend_path = "/spend/logs?request_id=fleetwork-permission-smoke-missing"
    checks: tuple[tuple[str, str, str, str, dict[str, Any] | None, str], ...] = (
        ("runner-chat", "runner", "POST", "/v1/chat/completions", chat, "allow"),
        (
            "runner-embedding",
            "runner",
            "POST",
            "/v1/embeddings",
            embedding,
            "allow",
        ),
        (
            "runner-spend-logs",
            "runner",
            "GET",
            spend_path,
            None,
            "deny",
        ),
        ("coordinator-chat", "coordinator", "POST", "/v1/chat/completions", chat, "allow"),
        (
            "coordinator-forbidden-model",
            "coordinator",
            "POST",
            "/v1/chat/completions",
            gpt4o_chat,
            "deny",
        ),
        (
            "coordinator-model-list-refusal",
            "coordinator",
            "GET",
            models_path,
            None,
            "deny",
        ),
        ("catalog-probe-models", "catalog-probe", "GET", models_path, None, "allow"),
        (
            "catalog-probe-chat",
            "catalog-probe",
            "POST",
            "/v1/chat/completions",
            gpt4o_chat,
            "allow",
        ),
        (
            "catalog-probe-embedding-refusal",
            "catalog-probe",
            "POST",
            "/v1/embeddings",
            embedding,
            "deny",
        ),
        (
            "catalog-probe-spend-refusal",
            "catalog-probe",
            "GET",
            spend_path,
            None,
            "deny",
        ),
        (
            "spend-reader-logs",
            "spend-reader",
            "GET",
            spend_path,
            None,
            "allow",
        ),
        (
            "spend-reader-chat-refusal",
            "spend-reader",
            "POST",
            "/v1/chat/completions",
            chat,
            "deny",
        ),
        (
            "spend-reader-model-list-refusal",
            "spend-reader",
            "GET",
            models_path,
            None,
            "deny",
        ),
    )
    report: list[dict[str, str | int]] = []
    for name, workload_id, method, path, payload, expectation in checks:
        status = http.request(base_url, keys[workload_id], method, path, payload)
        accepted = 200 <= status < 300 if expectation == "allow" else status == 403
        if not accepted:
            raise ReconcileError(
                f"workload smoke {name} expected {expectation} but returned HTTP {status}"
            )
        report.append({"check": name, "status": status})
    return {"status": "smoke-passed", "checks": report}


def reconcile(
    mode: str,
    workloads: tuple[Workload, ...],
    litellm: JsonClient,
    coolify: JsonClient | None = None,
    github_token: str = "",
    verify_secret_sinks: bool = True,
    rotate_workload: str | None = None,
) -> dict[str, Any]:
    rows = list_all_keys(litellm)
    indexed = index_managed_keys(rows, workloads)
    pending = {
        workload.id: rotation_candidates(rows, workload)
        for workload in workloads
    }
    sink_drift = (
        inspect_secret_sinks(workloads, indexed, coolify, github_token)
        if verify_secret_sinks
        else {}
    )
    if mode == "rotate":
        if not rotate_workload:
            raise ReconcileError("rotate requires --workload")
        selected = next(
            (workload for workload in workloads if workload.id == rotate_workload),
            None,
        )
        if selected is None:
            raise ReconcileError(f"unknown rotation workload {rotate_workload!r}")
        rotate_key(
            selected,
            indexed.get(selected.id),
            litellm,
            coolify,
            github_token,
        )
        return {
            "status": "rotated",
            "workloads": [{"workload": selected.id, "status": "rotated"}],
        }
    if mode == "apply" and sink_drift:
        affected = ", ".join(sorted(sink_drift))
        raise ReconcileError(
            "secret sink fingerprint mismatch; explicit credential rotation is required for: "
            + affected
        )
    pending_workloads = sorted(workload_id for workload_id, items in pending.items() if items)
    if mode == "apply" and pending_workloads:
        raise ReconcileError(
            "pending rotation candidates require explicit rotate recovery for: "
            + ", ".join(pending_workloads)
        )
    report: list[dict[str, Any]] = []
    changes: list[AppliedChange] = []
    try:
        for workload in workloads:
            current = indexed.get(workload.id)
            if current is None:
                item = {"workload": workload.id, "status": "missing"}
                if pending[workload.id]:
                    item["rotation"] = "pending"
                report.append(item)
                if mode == "apply":
                    secret, identifier = create_key_or_revoke_ambiguous(litellm, workload)
                    verified = next(
                        (
                            CurrentKey(_key_identifier(row), row)
                            for row in list_all_keys(litellm)
                            if _key_identifier(row) == identifier
                        ),
                        None,
                    )
                    if verified is None or drift_fields(verified.data, workload.desired):
                        litellm.post("/key/delete", {"keys": [identifier]})
                        raise ReconcileError(f"workload {workload.id} failed post-create verification")
                    try:
                        publish_secret(workload.sinks, secret, coolify, github_token)
                        published_drift = inspect_secret_sinks(
                            (workload,),
                            {workload.id: verified},
                            coolify,
                            github_token,
                        )
                    except Exception as error:
                        raise ReconcileError(
                            f"workload {workload.id} credential publication is incomplete; "
                            "the generated key was kept active to avoid a dead deployed secret"
                        ) from error
                    if published_drift:
                        raise ReconcileError(
                            f"workload {workload.id} secret fingerprint was not retained; "
                            "the generated key was kept active to avoid a dead deployed secret"
                        )
                continue

            drift = drift_fields(current.data, workload.desired)
            sinks = sink_drift.get(workload.id, [])
            if not drift and not sinks and not pending[workload.id]:
                report.append({"workload": workload.id, "status": "current"})
                continue
            item: dict[str, Any] = {"workload": workload.id, "status": "drift"}
            if drift:
                item["fields"] = drift
            if sinks:
                item["sinks"] = sinks
            if pending[workload.id]:
                item["rotation"] = "pending"
            report.append(item)
            if mode == "apply":
                previous = snapshot_for_rollback(current)
                changes.append(AppliedChange(workload, "updated", current.identifier, previous))
                litellm.post(
                    "/key/update",
                    desired_update(current.identifier, workload.desired),
                )
                verified = _find_by_alias(litellm, workload)
                if verified is None or drift_fields(verified.data, workload.desired):
                    raise ReconcileError(f"workload {workload.id} failed post-update verification")
    except Exception as error:
        rollback_errors: list[str] = []
        for change in reversed(changes):
            try:
                if change.previous is not None:
                    litellm.post("/key/update", change.previous)
            except Exception:
                rollback_errors.append(change.workload.id)
        if rollback_errors:
            raise ReconcileError(
                "key reconciliation failed and rollback is incomplete for: "
                + ", ".join(rollback_errors)
            ) from error
        if isinstance(error, ReconcileError):
            raise
        raise ReconcileError("key reconciliation failed and was rolled back") from error

    remaining = [item for item in report if item["status"] != "current"]
    return {
        "status": "applied" if mode == "apply" else ("drift" if remaining else "current"),
        "workloads": report,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("check", "apply", "rotate", "smoke"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--workload")
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    _, workloads = load_config(args.config, args.catalog)
    base_url = os.environ.get("LITELLM_BASE_URL", "").rstrip("/")
    admin_key = os.environ.get("LITELLM_ADMIN_KEY", "")
    if not base_url.startswith("https://") or not admin_key:
        raise ReconcileError("LITELLM_BASE_URL and LITELLM_ADMIN_KEY are required")
    litellm = JsonClient(base_url, admin_key, "fleetwork-litellm-key-reconciler/1")

    coolify = None
    coolify_url = os.environ.get("COOLIFY_URL", "").rstrip("/")
    coolify_token = os.environ.get("COOLIFY_API_TOKEN", "")
    if coolify_url.startswith("https://") and coolify_token:
        coolify = JsonClient(
            f"{coolify_url}/api/v1", coolify_token, "fleetwork-litellm-key-reconciler/1"
        )
    github_token = os.environ.get("FLEETWORK_GITHUB_WRITE_TOKEN", "")
    if args.mode == "smoke":
        indexed = index_managed_keys(list_all_keys(litellm), workloads)
        return smoke_workload_keys(
            workloads,
            indexed,
            coolify,
            dict(os.environ),
            base_url,
            SmokeHttpClient(),
        )
    return reconcile(
        args.mode,
        workloads,
        litellm,
        coolify,
        github_token,
        verify_secret_sinks=True,
        rotate_workload=args.workload,
    )


def main() -> int:
    try:
        result = run(build_parser().parse_args())
    except ReconcileError as error:
        print(f"LiteLLM key reconciliation refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 2 if result["status"] == "drift" else 0


if __name__ == "__main__":
    raise SystemExit(main())

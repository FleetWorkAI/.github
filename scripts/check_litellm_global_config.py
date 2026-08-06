#!/usr/bin/env python3
"""Fail-closed drift gate for the LiteLLM config mounted by Coolify."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if __package__:
    from scripts.reconcile_litellm_keys import JsonClient, ReconcileError
else:
    from reconcile_litellm_keys import JsonClient, ReconcileError


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
REQUIRED_SETTINGS = {
    "litellm_settings": {
        "include_cost_in_streaming_usage": True,
        "drop_params": False,
    },
    "router_settings": {
        "num_retries": 0,
        "max_fallbacks": 0,
    },
}


@dataclass(frozen=True)
class MountContract:
    service_uuid: str
    container_name: str
    compose_source: str
    host_source: str
    container_target: str
    ssh_user: str


@dataclass(frozen=True)
class GlobalConfigContract:
    source: Path
    semantic_digest: str
    mount: MountContract


def _scalar(value: str) -> bool | int | float | str | None:
    raw = value.strip()
    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", raw):
        return int(raw)
    if re.fullmatch(r"-?(?:[0-9]+\.[0-9]*|[0-9]*\.[0-9]+)", raw):
        return float(raw)
    if raw.lower() in ("null", "~"):
        return None
    if raw.startswith(('"', "'")):
        if len(raw) < 2 or raw[-1] != raw[0]:
            raise ReconcileError("invalid quoted YAML scalar")
        if raw[0] == '"':
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as error:
                raise ReconcileError("invalid quoted YAML scalar") from error
            if not isinstance(value, str):
                raise ReconcileError("invalid quoted YAML scalar")
            return value
        return raw[1:-1].replace("''", "'")
    if raw.startswith(("&", "*", "!", "|", ">")):
        raise ReconcileError("unsupported ambiguous YAML value")
    if not raw or raw[0] in ",[]{}#%@`":
        raise ReconcileError("invalid plain YAML scalar")
    if raw[0] in "-?:" and (len(raw) == 1 or raw[1].isspace()):
        raise ReconcileError("invalid plain YAML scalar")
    if re.search(r":(?:\s|$)", raw):
        raise ReconcileError("invalid plain YAML scalar")
    return raw


def _without_yaml_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(value):
        character = value[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if quote == '"' and character == "\\":
            escaped = True
            index += 1
            continue
        if character in ("'", '"'):
            if quote is None:
                quote = character
            elif quote == character:
                if quote == "'" and index + 1 < len(value) and value[index + 1] == "'":
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if character == "#" and quote is None and (
            index == 0 or value[index - 1].isspace()
        ):
            return value[:index].rstrip()
        index += 1
    if quote is not None:
        raise ReconcileError("unterminated quoted YAML scalar")
    return value.rstrip()


def _mapping_pair(value: str) -> tuple[str, str] | None:
    quote: str | None = None
    escaped = False
    depth = 0
    index = 0
    while index < len(value):
        character = value[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if quote == '"' and character == "\\":
            escaped = True
            index += 1
            continue
        if character in ("'", '"'):
            if quote is None:
                quote = character
            elif quote == character:
                if quote == "'" and index + 1 < len(value) and value[index + 1] == "'":
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if quote is not None:
            index += 1
            continue
        if character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ReconcileError("invalid YAML flow structure")
        elif character == ":" and depth == 0 and (
            index + 1 == len(value) or value[index + 1].isspace()
        ):
            raw_key = value[:index].strip()
            if not raw_key:
                raise ReconcileError("empty YAML mapping key")
            key = _scalar(raw_key)
            if not isinstance(key, str):
                raise ReconcileError("YAML mapping keys must be strings")
            return key, value[index + 1 :].strip()
        index += 1
    if quote is not None or depth != 0:
        raise ReconcileError("invalid YAML structure")
    return None


class _FlowParser:
    def __init__(self, value: str):
        self.value = value
        self.index = 0

    def parse(self) -> Any:
        result = self._value()
        self._space()
        if self.index != len(self.value):
            raise ReconcileError("invalid trailing YAML flow content")
        return result

    def _space(self) -> None:
        while self.index < len(self.value) and self.value[self.index].isspace():
            self.index += 1

    def _value(self) -> Any:
        self._space()
        if self.index >= len(self.value):
            raise ReconcileError("missing YAML flow value")
        character = self.value[self.index]
        if character == "{":
            return self._mapping()
        if character == "[":
            return self._sequence()
        if character in ("'", '"'):
            return self._quoted()
        start = self.index
        while self.index < len(self.value) and self.value[self.index] not in ",]}":
            self.index += 1
        raw = self.value[start : self.index].strip()
        if not raw:
            raise ReconcileError("missing YAML flow value")
        return _scalar(raw)

    def _quoted(self) -> str:
        quote = self.value[self.index]
        start = self.index
        self.index += 1
        while self.index < len(self.value):
            character = self.value[self.index]
            self.index += 1
            if quote == '"' and character == "\\":
                if self.index >= len(self.value):
                    break
                self.index += 1
                continue
            if character == quote:
                if quote == "'" and self.index < len(self.value) and self.value[self.index] == "'":
                    self.index += 1
                    continue
                value = _scalar(self.value[start : self.index])
                if not isinstance(value, str):
                    raise ReconcileError("invalid quoted YAML scalar")
                return value
        raise ReconcileError("unterminated quoted YAML scalar")

    def _mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        self.index += 1
        self._space()
        if self.index < len(self.value) and self.value[self.index] == "}":
            self.index += 1
            return result
        while True:
            key = self._flow_key()
            self._space()
            if self.index >= len(self.value) or self.value[self.index] != ":":
                raise ReconcileError("invalid YAML flow mapping")
            self.index += 1
            if key in result:
                raise ReconcileError("duplicate YAML mapping key")
            result[key] = self._value()
            self._space()
            if self.index >= len(self.value):
                raise ReconcileError("unterminated YAML flow mapping")
            separator = self.value[self.index]
            self.index += 1
            if separator == "}":
                return result
            if separator != ",":
                raise ReconcileError("invalid YAML flow mapping")

    def _flow_key(self) -> str:
        self._space()
        if self.index < len(self.value) and self.value[self.index] in ("'", '"'):
            return self._quoted()
        start = self.index
        while self.index < len(self.value) and self.value[self.index] != ":":
            if self.value[self.index] in "{},[]":
                raise ReconcileError("invalid YAML flow mapping key")
            self.index += 1
        raw = self.value[start : self.index].strip()
        if not raw:
            raise ReconcileError("empty YAML mapping key")
        key = _scalar(raw)
        if not isinstance(key, str):
            raise ReconcileError("YAML mapping keys must be strings")
        return key

    def _sequence(self) -> list[Any]:
        result: list[Any] = []
        self.index += 1
        self._space()
        if self.index < len(self.value) and self.value[self.index] == "]":
            self.index += 1
            return result
        while True:
            result.append(self._value())
            self._space()
            if self.index >= len(self.value):
                raise ReconcileError("unterminated YAML flow sequence")
            separator = self.value[self.index]
            self.index += 1
            if separator == "]":
                return result
            if separator != ",":
                raise ReconcileError("invalid YAML flow sequence")


class _StrictYamlParser:
    def __init__(self, text: str):
        self.lines: list[tuple[int, str]] = []
        if text.startswith("\ufeff"):
            raise ReconcileError("YAML byte-order marks are not supported")
        for raw_line in text.splitlines():
            if "\t" in raw_line[: len(raw_line) - len(raw_line.lstrip())]:
                raise ReconcileError("YAML indentation must use spaces")
            content = _without_yaml_comment(raw_line).rstrip()
            if not content.strip():
                continue
            indent = len(content) - len(content.lstrip(" "))
            stripped = content[indent:]
            if stripped.startswith("%") or stripped in ("---", "..."):
                raise ReconcileError("multiple or directed YAML documents are not supported")
            self.lines.append((indent, stripped))

    def parse(self) -> Any:
        if not self.lines:
            raise ReconcileError("empty YAML document")
        if self.lines[0][0] != 0:
            raise ReconcileError("YAML root must not be indented")
        result, index = self._node(0, 0)
        if index != len(self.lines):
            raise ReconcileError("invalid YAML indentation")
        return result

    def _node(self, index: int, indent: int) -> tuple[Any, int]:
        if self.lines[index][0] != indent:
            raise ReconcileError("invalid YAML indentation")
        if self.lines[index][1] == "-" or self.lines[index][1].startswith("- "):
            return self._sequence(index, indent)
        return self._mapping(index, indent)

    def _nested(self, index: int, parent_indent: int) -> tuple[Any, int]:
        if index >= len(self.lines) or self.lines[index][0] <= parent_indent:
            return None, index
        return self._node(index, self.lines[index][0])

    def _mapping(
        self,
        index: int,
        indent: int,
        initial: tuple[str, str] | None = None,
    ) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        if initial is not None:
            index = self._mapping_value(result, initial, index, indent)
        while index < len(self.lines) and self.lines[index][0] == indent:
            content = self.lines[index][1]
            if content == "-" or content.startswith("- "):
                break
            pair = _mapping_pair(content)
            if pair is None:
                raise ReconcileError("invalid YAML mapping entry")
            index = self._mapping_value(result, pair, index + 1, indent)
        return result, index

    def _mapping_value(
        self,
        result: dict[str, Any],
        pair: tuple[str, str],
        next_index: int,
        indent: int,
    ) -> int:
        key, raw_value = pair
        if key in result:
            raise ReconcileError("duplicate YAML mapping key")
        if raw_value:
            result[key] = self._inline_value(raw_value)
            return next_index
        result[key], next_index = self._nested(next_index, indent)
        return next_index

    def _sequence(self, index: int, indent: int) -> tuple[list[Any], int]:
        result: list[Any] = []
        while index < len(self.lines) and self.lines[index][0] == indent:
            content = self.lines[index][1]
            if content != "-" and not content.startswith("- "):
                break
            raw_value = content[1:].strip()
            index += 1
            if not raw_value:
                value, index = self._nested(index, indent)
                if value is None:
                    raise ReconcileError("missing YAML sequence value")
                result.append(value)
                continue
            pair = _mapping_pair(raw_value)
            if pair is not None:
                child_indent = indent + 2
                value, index = self._mapping(index, child_indent, pair)
                result.append(value)
                continue
            result.append(self._inline_value(raw_value))
            if index < len(self.lines) and self.lines[index][0] > indent:
                raise ReconcileError("scalar YAML sequence item cannot have children")
        return result, index

    @staticmethod
    def _inline_value(value: str) -> Any:
        if value.startswith(("{", "[")):
            return _FlowParser(value).parse()
        return _scalar(value)


def _load_yaml(text: str, purpose: str) -> Any:
    try:
        return _StrictYamlParser(text).parse()
    except ReconcileError as error:
        raise ReconcileError(f"invalid {purpose} YAML: {error}") from error


def governed_settings(text: str) -> dict[str, dict[str, bool | int | str]]:
    """Parse YAML strictly, then return only the four non-secret policy values."""
    document = _load_yaml(text, "LiteLLM config")
    if not isinstance(document, dict):
        raise ReconcileError("LiteLLM config YAML root must be a mapping")
    found: dict[str, dict[str, bool | int | str]] = {}
    for section, required in REQUIRED_SETTINGS.items():
        raw_section = document.get(section)
        if raw_section is None:
            found[section] = {}
            continue
        if not isinstance(raw_section, dict):
            raise ReconcileError(f"{section} must be a YAML mapping")
        found[section] = {}
        for key, expected in required.items():
            if key not in raw_section:
                continue
            value = raw_section[key]
            if type(value) is not type(expected):
                raise ReconcileError(f"{section}.{key} has an invalid YAML type")
            found[section][key] = value
    return found


def settings_digest(settings: dict[str, dict[str, Any]]) -> str:
    """Hash canonical JSON so YAML ordering, comments, and whitespace do not matter."""
    canonical = json.dumps(settings, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _required_string(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise ReconcileError(f"global config contract {key} must be a non-empty string")
    return value


def load_contract(path: Path, repository_root: Path) -> GlobalConfigContract:
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ReconcileError(f"cannot read global config contract {path}") from error
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise ReconcileError("unsupported global config contract schema")
    if raw.get("litellmVersion") != "1.83.10":
        raise ReconcileError("global config contract must target LiteLLM 1.83.10")
    source_ref = _required_string(raw, "settingsSource")
    source = (repository_root / source_ref).resolve()
    root = repository_root.resolve()
    if source != root and root not in source.parents:
        raise ReconcileError("global settings source escapes the repository")
    expected_digest = _required_string(raw, "settingsSemanticDigest")
    if not DIGEST_RE.fullmatch(expected_digest):
        raise ReconcileError("global settings digest must be sha256")
    try:
        desired = governed_settings(source.read_text())
    except OSError as error:
        raise ReconcileError(f"cannot read global settings source {source}") from error
    if desired != REQUIRED_SETTINGS:
        raise ReconcileError("global settings source does not match the mandatory policy")
    if settings_digest(desired) != expected_digest:
        raise ReconcileError("global settings digest is stale")

    coolify = raw.get("coolify")
    if not isinstance(coolify, dict):
        raise ReconcileError("global config contract coolify must be an object")
    mount = MountContract(
        service_uuid=_required_string(coolify, "serviceUuid"),
        container_name=_required_string(coolify, "containerName"),
        compose_source=_required_string(coolify, "composeSource"),
        host_source=_required_string(coolify, "hostSource"),
        container_target=_required_string(coolify, "containerTarget"),
        ssh_user=_required_string(coolify, "sshUser"),
    )
    if not all(
        IDENTIFIER_RE.fullmatch(value)
        for value in (
            mount.service_uuid,
            mount.container_name,
            mount.ssh_user,
        )
    ):
        raise ReconcileError("global config contract contains an unsafe identifier")
    expected_host = f"/data/coolify/services/{mount.service_uuid}/litellm-config.yaml"
    if (
        mount.compose_source != "./litellm-config.yaml"
        or mount.host_source != expected_host
        or mount.container_target != "/app/config.yaml"
        or mount.ssh_user != "debian"
    ):
        raise ReconcileError("global config contract contains an unsafe mount or SSH target")
    return GlobalConfigContract(source, expected_digest, mount)


def check_actual_config(contract: GlobalConfigContract, actual_text: str) -> dict[str, str]:
    actual = governed_settings(actual_text)
    drift = [
        f"{section}.{key}"
        for section, required in REQUIRED_SETTINGS.items()
        for key, expected in required.items()
        if actual.get(section, {}).get(key) != expected
    ]
    if drift:
        raise ReconcileError("LiteLLM global config drift: " + ", ".join(drift))
    digest = settings_digest(actual)
    if digest != contract.semantic_digest:
        raise ReconcileError("LiteLLM global config digest mismatch")
    return {"status": "current", "settingsSemanticDigest": digest}


def check_coolify_mount(contract: GlobalConfigContract, coolify: JsonClient) -> dict[str, str]:
    mount = contract.mount
    service = coolify.get(f"/services/{mount.service_uuid}")
    if not isinstance(service, dict):
        raise ReconcileError("Coolify returned an invalid LiteLLM service")
    if service.get("uuid") != mount.service_uuid:
        raise ReconcileError("Coolify LiteLLM service UUID drift")
    raw = service.get("docker_compose_raw")
    rendered = service.get("docker_compose")
    if not isinstance(raw, str) or not isinstance(rendered, str):
        raise ReconcileError("Coolify did not return both LiteLLM compose documents")
    raw_services = _compose_services(raw, "raw Coolify compose")
    rendered_services = _compose_services(rendered, "rendered Coolify compose")
    raw_litellm = raw_services.get("litellm")
    rendered_litellm = rendered_services.get("litellm")
    if not isinstance(raw_litellm, dict) or not isinstance(rendered_litellm, dict):
        raise ReconcileError("Coolify LiteLLM compose service drift")
    if rendered_litellm.get("container_name") != mount.container_name:
        raise ReconcileError("Coolify LiteLLM container identity drift")
    if not _has_bind_mount(
        raw_litellm.get("volumes"), mount.compose_source, mount.container_target
    ):
        raise ReconcileError("Coolify LiteLLM source mount drift")
    if not _has_bind_mount(
        rendered_litellm.get("volumes"), mount.host_source, mount.container_target
    ):
        raise ReconcileError("Coolify LiteLLM rendered mount drift")
    return {"status": "current", "serviceUuid": mount.service_uuid}


def _compose_services(text: str, purpose: str) -> dict[str, Any]:
    document = _load_yaml(text, purpose)
    if not isinstance(document, dict):
        raise ReconcileError(f"{purpose} root must be a mapping")
    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise ReconcileError(f"{purpose} services must be a non-empty mapping")
    if not all(isinstance(name, str) and isinstance(value, dict) for name, value in services.items()):
        raise ReconcileError(f"{purpose} contains an invalid service")
    return services


def _has_bind_mount(volumes: Any, source: str, target: str) -> bool:
    if not isinstance(volumes, list):
        return False
    target_mounts: list[bool] = []
    for volume in volumes:
        if isinstance(volume, dict):
            if volume.get("target") == target:
                target_mounts.append(
                    volume.get("type") == "bind" and volume.get("source") == source
                )
            continue
        if not isinstance(volume, str):
            continue
        parts = volume.split(":")
        if len(parts) in (2, 3) and parts[1] == target:
            target_mounts.append(parts[0] == source)
    return target_mounts == [True]


def _read_remote_text(
    contract: GlobalConfigContract,
    host: str,
    port: int,
    identity_file: Path,
    known_hosts_file: Path,
    remote_command: list[str],
    target_name: str,
) -> str:
    if not HOST_RE.fullmatch(host) or not 1 <= port <= 65535:
        raise ReconcileError("invalid LiteLLM config SSH endpoint")
    if not identity_file.is_file() or not known_hosts_file.is_file():
        raise ReconcileError("LiteLLM config SSH identity and known_hosts are required")
    mount = contract.mount
    command = [
        "ssh",
        "-F",
        "/dev/null",
        "-i",
        str(identity_file),
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts_file}",
        f"{mount.ssh_user}@{host}",
        *remote_command,
    ]
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReconcileError(f"could not read the {target_name} LiteLLM config over SSH") from error
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReconcileError(f"{target_name} LiteLLM config is not UTF-8") from error


def read_remote_configs(
    contract: GlobalConfigContract,
    host: str,
    port: int,
    identity_file: Path,
    known_hosts_file: Path,
) -> tuple[str, str]:
    """Read the host bind source and the runtime target without logging either file."""
    mount = contract.mount
    mounted = _read_remote_text(
        contract,
        host,
        port,
        identity_file,
        known_hosts_file,
        ["sudo", "-n", "cat", mount.host_source],
        "host-mounted",
    )
    runtime = _read_remote_text(
        contract,
        host,
        port,
        identity_file,
        known_hosts_file,
        [
            "sudo",
            "-n",
            "docker",
            "exec",
            mount.container_name,
            "cat",
            mount.container_target,
        ],
        "runtime",
    )
    return mounted, runtime


def check_remote_configs(
    contract: GlobalConfigContract,
    mounted_text: str,
    runtime_text: str,
) -> dict[str, str]:
    """Compare the source policy with both live copies, then prove the bind is exact."""
    mounted = check_actual_config(contract, mounted_text)
    runtime = check_actual_config(contract, runtime_text)
    mounted_bytes = hashlib.sha256(mounted_text.encode("utf-8")).digest()
    runtime_bytes = hashlib.sha256(runtime_text.encode("utf-8")).digest()
    if mounted_bytes != runtime_bytes:
        raise ReconcileError("LiteLLM host-mounted and runtime config files differ")
    if mounted["settingsSemanticDigest"] != runtime["settingsSemanticDigest"]:
        raise ReconcileError("LiteLLM host-mounted and runtime policy digests differ")
    return {
        "status": "current",
        "settingsSemanticDigest": mounted["settingsSemanticDigest"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("validate", "check", "check-live"))
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--actual", default="-")
    parser.add_argument("--ssh-identity", type=Path)
    parser.add_argument("--ssh-known-hosts", type=Path)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    contract = load_contract(args.contract, args.repository_root)
    if args.mode == "validate":
        return {"status": "valid", "settingsSemanticDigest": contract.semantic_digest}
    if args.mode == "check":
        actual = sys.stdin.read() if args.actual == "-" else Path(args.actual).read_text()
        return check_actual_config(contract, actual)

    coolify_url = os.environ.get("COOLIFY_URL", "").rstrip("/")
    coolify_token = os.environ.get("COOLIFY_API_TOKEN", "")
    host = os.environ.get("FLEETWORK_PRODUCTION_SSH_HOST", "")
    port_raw = os.environ.get("FLEETWORK_PRODUCTION_SSH_PORT", "")
    if not coolify_url.startswith("https://") or not coolify_token:
        raise ReconcileError("COOLIFY_URL and COOLIFY_API_TOKEN are required")
    try:
        port = int(port_raw)
    except ValueError as error:
        raise ReconcileError("FLEETWORK_PRODUCTION_SSH_PORT must be an integer") from error
    if args.ssh_identity is None or args.ssh_known_hosts is None:
        raise ReconcileError("check-live requires SSH identity and known_hosts paths")
    coolify = JsonClient(
        f"{coolify_url}/api/v1", coolify_token, "fleetwork-litellm-global-config/1"
    )
    mount_report = check_coolify_mount(contract, coolify)
    mounted, runtime = read_remote_configs(
        contract, host, port, args.ssh_identity, args.ssh_known_hosts
    )
    config_report = check_remote_configs(contract, mounted, runtime)
    return {
        "status": "current",
        "serviceUuid": mount_report["serviceUuid"],
        "settingsSemanticDigest": config_report["settingsSemanticDigest"],
        "checkedCopies": ["versioned-source", "host-mounted", "runtime"],
    }


def main() -> int:
    try:
        result = run(build_parser().parse_args())
    except (OSError, ReconcileError) as error:
        print(f"LiteLLM global config gate refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

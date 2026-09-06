"""Fail-closed structural policy for imported Compose documents."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, cast

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.tokens import AliasToken, AnchorToken

from .errors import IntegrityError
from .models import DIGEST

ROOT_KEYS = {"name", "version", "services", "networks", "volumes"}
SERVICE_KEYS = {
    "image",
    "command",
    "entrypoint",
    "environment",
    "expose",
    "ports",
    "networks",
    "volumes",
    "depends_on",
    "healthcheck",
    "restart",
    "read_only",
    "tmpfs",
    "cap_drop",
    "cap_add",
    "security_opt",
    "user",
    "working_dir",
    "stop_grace_period",
    "deploy",
    "init",
    "hostname",
}
DANGEROUS_KEYS = {
    "privileged",
    "network_mode",
    "pid",
    "ipc",
    "userns_mode",
    "devices",
    "device_cgroup_rules",
    "build",
    "extends",
    "external_links",
    "links",
    "uts",
    "cgroup",
    "cgroup_parent",
    "sysctls",
    "configs",
    "secrets",
    "credential_spec",
    "runtime",
    "isolation",
    "pull_policy",
    "platform",
    "env_file",
    "container_name",
}
SAFE_CAPABILITIES = {"NET_BIND_SERVICE"}
SERVICE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
NON_ROOT_USER = re.compile(r"^[1-9][0-9]{0,9}(?::[1-9][0-9]{0,9})?$")
MEMORY_LIMIT = re.compile(r"^([1-9][0-9]{0,8})([KMG])$")
LOOPBACK_PORT = re.compile(r"^127\.0\.0\.1:([1-9][0-9]{0,4}):([1-9][0-9]{0,4})(?:/tcp)?$")


class UniqueSafeLoader(yaml.SafeLoader):
    """Safe loader that rejects duplicate mapping keys instead of overwriting them."""


def _construct_unique_mapping(
    loader: UniqueSafeLoader, node: MappingNode, deep: bool = False
) -> dict[object, object]:
    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping", node.start_mark, "unhashable key"
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


@dataclass(frozen=True)
class Finding:
    path: str
    reason: str


@dataclass(frozen=True)
class ComposeReview:
    accepted: bool
    findings: tuple[Finding, ...]


def load_compose(content: bytes) -> dict[str, Any]:
    if len(content) > 2_000_000:
        raise IntegrityError("Compose document exceeds 2 MB")
    if b"\x00" in content:
        raise IntegrityError("Compose document contains a NUL byte")
    try:
        if any(isinstance(token, AliasToken | AnchorToken) for token in yaml.scan(content)):
            raise IntegrityError("Compose YAML anchors and aliases are forbidden")
        value = yaml.load(content, Loader=UniqueSafeLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise IntegrityError(f"Compose YAML is invalid: {exc}") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise IntegrityError("Compose root must be a string-keyed object")
    return cast(dict[str, Any], value)


def _contains_interpolation(value: object) -> bool:
    if isinstance(value, str):
        return "${" in value or "\x00" in value
    if isinstance(value, list):
        return any(_contains_interpolation(item) for item in value)
    if isinstance(value, dict):
        return any(
            _contains_interpolation(key) or _contains_interpolation(item)
            for key, item in value.items()
        )
    return False


def _volume_safe(value: object, declared: set[str]) -> bool:
    if isinstance(value, str):
        source, separator, target = value.partition(":")
        return bool(
            separator
            and source in declared
            and target.startswith("/")
            and ".." not in target.split("/")
        )
    if isinstance(value, dict):
        volume_options = value.get("volume")
        return (
            value.get("type") == "volume"
            and isinstance(value.get("source"), str)
            and value["source"] in declared
            and isinstance(value.get("target"), str)
            and value["target"].startswith("/")
            and set(value).issubset({"type", "source", "target", "read_only", "volume"})
            and ("read_only" not in value or isinstance(value["read_only"], bool))
            and (
                volume_options is None
                or (
                    isinstance(volume_options, dict)
                    and set(volume_options) == {"nocopy"}
                    and isinstance(volume_options["nocopy"], bool)
                )
            )
        )
    return False


def _port_safe(value: object, *, gateway: bool) -> bool:
    if not gateway:
        return False
    if isinstance(value, str):
        match = LOOPBACK_PORT.fullmatch(value)
        return match is not None and all(1 <= int(port) <= 65535 for port in match.groups())
    if isinstance(value, dict):
        return (
            value.get("host_ip") == "127.0.0.1"
            and isinstance(value.get("published"), int)
            and not isinstance(value["published"], bool)
            and 1 <= value["published"] <= 65535
            and isinstance(value.get("target"), int)
            and not isinstance(value["target"], bool)
            and 1 <= value["target"] <= 65535
            and set(value).issubset({"host_ip", "published", "target", "protocol", "mode"})
            and value.get("protocol", "tcp") == "tcp"
            and value.get("mode", "host") == "host"
        )
    return False


def _non_root_user_safe(value: object) -> bool:
    if not isinstance(value, str) or NON_ROOT_USER.fullmatch(value) is None:
        return False
    return all(1 <= int(identifier) <= 2_147_483_647 for identifier in value.split(":"))


def _resource_limits_safe(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"resources"}:
        return False
    resources = value["resources"]
    if not isinstance(resources, dict) or set(resources) != {"limits"}:
        return False
    limits = resources["limits"]
    if not isinstance(limits, dict) or set(limits) != {"memory", "cpus", "pids"}:
        return False

    memory = limits["memory"]
    match = MEMORY_LIMIT.fullmatch(memory) if isinstance(memory, str) else None
    if match is None:
        return False
    multiplier = {"K": 1024, "M": 1024**2, "G": 1024**3}[match.group(2)]
    memory_bytes = int(match.group(1)) * multiplier
    if not 64 * 1024**2 <= memory_bytes <= 128 * 1024**3:
        return False

    cpus = limits["cpus"]
    if isinstance(cpus, bool) or not isinstance(cpus, str | int | float):
        return False
    try:
        cpu_limit = Decimal(str(cpus))
    except InvalidOperation:
        return False
    if not cpu_limit.is_finite() or not Decimal("0.1") <= cpu_limit <= Decimal("64"):
        return False

    pids = limits["pids"]
    return isinstance(pids, int) and not isinstance(pids, bool) and 16 <= pids <= 32_768


def validate_compose(
    document: dict[str, Any],
    *,
    approved_images: set[str],
    allow_commands: set[str] | None = None,
) -> ComposeReview:
    findings: list[Finding] = []
    unknown_root = set(document) - ROOT_KEYS
    for key in sorted(unknown_root):
        findings.append(Finding(key, "arbitrary Compose root key or extension is not allowed"))
    if _contains_interpolation(document):
        findings.append(
            Finding("$", "environment interpolation is not allowed in imported Compose")
        )
    version = document.get("version")
    if version is not None and (
        not isinstance(version, str) or re.fullmatch(r"[23](?:\.[0-9]+)?", version) is None
    ):
        findings.append(Finding("version", "legacy Compose version is malformed"))
    services = document.get("services")
    if not isinstance(services, dict) or not services:
        findings.append(Finding("services", "a non-empty service map is required"))
        return ComposeReview(False, tuple(findings))
    volumes = document.get("volumes", {})
    declared_volumes = (
        {name for name in volumes if isinstance(name, str)} if isinstance(volumes, dict) else set()
    )
    if not isinstance(volumes, dict):
        findings.append(Finding("volumes", "top-level volumes must be an object"))
    elif any(
        not isinstance(name, str)
        or SERVICE_NAME.fullmatch(name) is None
        or not isinstance(value, dict)
        or value
        for name, value in volumes.items()
    ):
        findings.append(
            Finding("volumes", "external, named, and driver-configured volumes are forbidden")
        )
    networks = document.get("networks")
    if not isinstance(networks, dict) or not networks:
        findings.append(Finding("networks", "explicit internal networks are required"))
    else:
        for name, value in networks.items():
            if (
                not isinstance(name, str)
                or SERVICE_NAME.fullmatch(name) is None
                or not isinstance(value, dict)
                or value != {"internal": True}
            ):
                findings.append(
                    Finding(
                        f"networks.{name}",
                        "provider networks must be internal and may not use external options",
                    )
                )
    commands = allow_commands or set()
    for name, raw in services.items():
        path = f"services.{name}"
        if (
            not isinstance(name, str)
            or SERVICE_NAME.fullmatch(name) is None
            or not isinstance(raw, dict)
            or not all(isinstance(key, str) for key in raw)
        ):
            findings.append(Finding(path, "service must be a string-keyed object"))
            continue
        service = cast(dict[str, Any], raw)
        for key in sorted(set(service) & DANGEROUS_KEYS):
            findings.append(Finding(f"{path}.{key}", "dangerous Compose capability is forbidden"))
        for key in sorted(set(service) - SERVICE_KEYS - DANGEROUS_KEYS):
            findings.append(Finding(f"{path}.{key}", "unreviewed Compose service key is forbidden"))
        image = service.get("image")
        if not isinstance(image, str) or "@" not in image:
            findings.append(Finding(f"{path}.image", "image must be digest-pinned"))
        else:
            _, digest = image.rsplit("@", 1)
            if not DIGEST.fullmatch(digest) or image not in approved_images:
                findings.append(
                    Finding(f"{path}.image", "image provenance and digest are not allowlisted")
                )
        if service.get("restart", "no") != "no":
            findings.append(Finding(f"{path}.restart", "automatic restart is forbidden"))
        if service.get("read_only") is not True:
            findings.append(Finding(f"{path}.read_only", "a read-only root filesystem is required"))
        cap_add = service.get("cap_add", [])
        if not isinstance(cap_add, list) or not all(isinstance(value, str) for value in cap_add):
            cap_add_safe = False
        else:
            cap_add_safe = all(value in SAFE_CAPABILITIES for value in cap_add) and len(
                cap_add
            ) == len(set(cap_add))
        if not cap_add_safe:
            findings.append(
                Finding(f"{path}.cap_add", "kernel capability is not explicitly allowlisted")
            )
        cap_drop = service.get("cap_drop", [])
        if cap_drop != ["ALL"]:
            findings.append(Finding(f"{path}.cap_drop", "cap_drop must be exactly [ALL]"))
        security = service.get("security_opt")
        if security != ["no-new-privileges:true"]:
            findings.append(
                Finding(
                    f"{path}.security_opt",
                    "security_opt must contain only no-new-privileges:true",
                )
            )
        user = service.get("user")
        if not _non_root_user_safe(user):
            findings.append(
                Finding(f"{path}.user", "an explicit positive numeric non-root UID is required")
            )
        if "init" in service and service["init"] is not True:
            findings.append(Finding(f"{path}.init", "init must be true when specified"))
        if "command" in service and name not in commands:
            findings.append(
                Finding(f"{path}.command", "imported commands require entry-specific review")
            )
        if "entrypoint" in service and name not in commands:
            findings.append(
                Finding(f"{path}.entrypoint", "imported entrypoints require entry-specific review")
            )
        service_volumes = service.get("volumes", [])
        if not isinstance(service_volumes, list) or any(
            not _volume_safe(value, declared_volumes) for value in service_volumes
        ):
            findings.append(
                Finding(
                    f"{path}.volumes",
                    "only declared named volumes with absolute targets are allowed",
                )
            )
        service_ports = service.get("ports", [])
        if (
            not isinstance(service_ports, list)
            or len(service_ports) > 1
            or any(not _port_safe(value, gateway=name == "gateway") for value in service_ports)
        ):
            findings.append(
                Finding(
                    f"{path}.ports",
                    "ports are forbidden except bounded loopback gateway publication",
                )
            )
        service_networks = service.get("networks")
        if not isinstance(service_networks, list) or not service_networks:
            findings.append(Finding(f"{path}.networks", "explicit internal networks are required"))
        elif (
            not all(isinstance(value, str) for value in service_networks)
            or len(service_networks) != len(set(service_networks))
            or not isinstance(networks, dict)
            or any(value not in networks for value in service_networks)
        ):
            findings.append(Finding(f"{path}.networks", "service uses an undeclared network"))
        deploy = service.get("deploy")
        if not _resource_limits_safe(deploy):
            findings.append(
                Finding(
                    f"{path}.deploy.resources.limits",
                    "exact bounded memory, CPU, and PID limits are required",
                )
            )
    return ComposeReview(not findings, tuple(findings))

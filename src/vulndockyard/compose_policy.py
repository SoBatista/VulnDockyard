"""Fail-closed structural policy for imported Compose documents."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, cast

import yaml

from .errors import IntegrityError
from .models import DIGEST

ROOT_KEYS = {"name", "services", "networks", "volumes"}
SERVICE_KEYS = {
    "image",
    "container_name",
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
}
SAFE_CAPABILITIES = {"NET_BIND_SERVICE"}


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
        value = yaml.safe_load(content)
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
        return (
            value.get("type") == "volume"
            and isinstance(value.get("source"), str)
            and value["source"] in declared
            and isinstance(value.get("target"), str)
            and value["target"].startswith("/")
            and set(value).issubset({"type", "source", "target", "read_only", "volume"})
        )
    return False


def _port_safe(value: object, *, gateway: bool) -> bool:
    if not gateway:
        return False
    if isinstance(value, str):
        return (
            re.fullmatch(r"127\.0\.0\.1:(80|[1-9][0-9]{3,4}):[1-9][0-9]{0,4}(/tcp)?", value)
            is not None
        )
    if isinstance(value, dict):
        return (
            value.get("host_ip") == "127.0.0.1"
            and isinstance(value.get("published"), int)
            and 1 <= value["published"] <= 65535
            and isinstance(value.get("target"), int)
            and 1 <= value["target"] <= 65535
            and set(value).issubset({"host_ip", "published", "target", "protocol", "mode"})
            and value.get("mode", "host") == "host"
        )
    return False


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
    services = document.get("services")
    if not isinstance(services, dict) or not services:
        findings.append(Finding("services", "a non-empty service map is required"))
        return ComposeReview(False, tuple(findings))
    volumes = document.get("volumes", {})
    declared_volumes = set(volumes) if isinstance(volumes, dict) else set()
    if not isinstance(volumes, dict):
        findings.append(Finding("volumes", "top-level volumes must be an object"))
    elif any(not isinstance(value, dict) or value for value in volumes.values()):
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
        if not isinstance(name, str) or not isinstance(raw, dict):
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
        if service.get("restart", "no") not in {"no", "none"}:
            findings.append(Finding(f"{path}.restart", "automatic restart is forbidden"))
        if service.get("read_only") is not True:
            findings.append(Finding(f"{path}.read_only", "a read-only root filesystem is required"))
        cap_add = service.get("cap_add", [])
        if not isinstance(cap_add, list) or any(
            value not in SAFE_CAPABILITIES for value in cap_add
        ):
            findings.append(
                Finding(f"{path}.cap_add", "kernel capability is not explicitly allowlisted")
            )
        cap_drop = service.get("cap_drop", [])
        if not isinstance(cap_drop, list) or "ALL" not in cap_drop:
            findings.append(Finding(f"{path}.cap_drop", "cap_drop must include ALL"))
        security = service.get("security_opt", [])
        if not isinstance(security, list) or "no-new-privileges:true" not in security:
            findings.append(Finding(f"{path}.security_opt", "no-new-privileges is required"))
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
        if not isinstance(service_ports, list) or any(
            not _port_safe(value, gateway=name == "gateway") for value in service_ports
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
        elif not isinstance(networks, dict) or any(
            not isinstance(value, str) or value not in networks for value in service_networks
        ):
            findings.append(Finding(f"{path}.networks", "service uses an undeclared network"))
        deploy = service.get("deploy")
        if not isinstance(deploy, dict) or not isinstance(deploy.get("resources"), dict):
            findings.append(
                Finding(f"{path}.deploy.resources", "explicit resource limits are required")
            )
    return ComposeReview(not findings, tuple(findings))

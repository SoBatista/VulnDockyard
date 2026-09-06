"""Strict reviewed manifest and lockfile models."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, cast
from urllib.parse import urlparse

from .errors import IntegrityError

LAB_ID = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
HOSTNAME = re.compile(r"^[a-z][a-z0-9-]{0,61}\.test$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ISO_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
PLATFORM = re.compile(r"^linux/(amd64|arm64|arm/v7)$")
OCI_NAME = re.compile(
    r"^(?=.{3,255}$)(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|localhost)(?::[1-9][0-9]{0,4})?/"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
EPHEMERAL_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
MAX_EPHEMERAL_MOUNTS = 32
MAX_EPHEMERAL_SIZE_MB = 4_096
MAX_EPHEMERAL_TOTAL_MB = 8_192
MAX_CONTAINER_PATH_LENGTH = 4_096


class TrustLevel(StrEnum):
    UPSTREAM_SIGNED = "upstream-signed"
    UPSTREAM_PINNED = "upstream-pinned"
    VULNDOCKYARD_BUILT = "vulndockyard-built"
    QUARANTINED = "quarantined"


class AdapterStatus(StrEnum):
    RUNNABLE = "runnable"
    QUARANTINED = "quarantined"
    UNAVAILABLE = "unavailable"


def _mapping(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise IntegrityError(f"{context} must be an object")
    return cast(dict[str, Any], value)


def _sequence(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise IntegrityError(f"{context} must be an array")
    return value


def _string(value: object, context: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise IntegrityError(f"{context} must be a non-empty string")
    return value


def _string_list(value: object, context: str) -> tuple[str, ...]:
    return tuple(_string(item, context) for item in _sequence(value, context))


def _https_list(value: object, context: str) -> tuple[str, ...]:
    values = _string_list(value, context)
    for item in values:
        parsed = urlparse(item)
        if parsed.scheme != "https" or not parsed.netloc:
            raise IntegrityError(f"{context} must contain only https URLs")
    return values


def _platform_list(value: object, context: str) -> tuple[str, ...]:
    values = _string_list(value, context)
    if len(values) != len(set(values)) or any(PLATFORM.fullmatch(item) is None for item in values):
        raise IntegrityError(f"{context} contains an unsupported or duplicate platform")
    return values


def _date(value: object, context: str) -> date:
    text = _string(value, context)
    if ISO_DATE.fullmatch(text) is None:
        raise IntegrityError(f"{context} must be an ISO 8601 calendar date")
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise IntegrityError(f"{context} must be an ISO 8601 calendar date") from exc


def _utc_timestamp(value: object, context: str) -> datetime:
    text = _string(value, context)
    if UTC_TIMESTAMP.fullmatch(text) is None:
        raise IntegrityError(f"{context} must be a UTC ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntegrityError(f"{context} must be a UTC ISO 8601 timestamp") from exc
    if parsed.tzinfo != UTC:
        raise IntegrityError(f"{context} must be a UTC ISO 8601 timestamp")
    return parsed


def _require_exact(data: dict[str, Any], keys: set[str], context: str) -> None:
    missing = sorted(keys - data.keys())
    unknown = sorted(data.keys() - keys)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise IntegrityError(f"{context}: {'; '.join(details)}")


@dataclass(frozen=True)
class Image:
    name: str
    digest: str
    architectures: tuple[str, ...]
    role: str

    @classmethod
    def parse(cls, value: object) -> Image:
        data = _mapping(value, "image")
        _require_exact(data, {"name", "digest", "architectures", "role"}, "image")
        name = _string(data["name"], "image.name")
        digest = _string(data["digest"], "image.digest", allow_empty=True)
        if OCI_NAME.fullmatch(name) is None:
            raise IntegrityError("image.name must be a canonical fully qualified OCI repository")
        if digest and not DIGEST.fullmatch(digest):
            raise IntegrityError("image.digest must be an immutable sha256 digest")
        architectures = _platform_list(data["architectures"], "image.architectures")
        return cls(
            name,
            digest,
            architectures,
            _string(data["role"], "role"),
        )

    @property
    def reference(self) -> str:
        if not self.digest:
            raise IntegrityError(f"image {self.name} has no reviewed digest")
        return f"{self.name}@{self.digest}"


@dataclass(frozen=True)
class Service:
    name: str
    image_role: str
    internal_port: int
    protocol: str
    health_path: str
    identity_marker: str

    @classmethod
    def parse(cls, value: object) -> Service:
        data = _mapping(value, "service")
        keys = {
            "name",
            "image_role",
            "internal_port",
            "protocol",
            "health_path",
            "identity_marker",
        }
        _require_exact(data, keys, "service")
        port = data["internal_port"]
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise IntegrityError("service.internal_port must be between 1 and 65535")
        protocol = _string(data["protocol"], "service.protocol")
        if protocol not in {"http", "https", "tcp"}:
            raise IntegrityError("service.protocol is not supported")
        path = _string(data["health_path"], "service.health_path")
        if (
            not path.startswith("/")
            or path.startswith("//")
            or len(path) > 512
            or not path.isascii()
            or not path.isprintable()
            or "#" in path
        ):
            raise IntegrityError("service.health_path must be a safe origin-relative HTTP path")
        identity_marker = _string(data["identity_marker"], "service.identity_marker")
        if len(identity_marker) > 160 or not identity_marker.isprintable():
            raise IntegrityError(
                "service.identity_marker must be a printable literal up to 160 characters"
            )
        return cls(
            _string(data["name"], "service.name"),
            _string(data["image_role"], "service.image_role"),
            port,
            protocol,
            path,
            identity_marker,
        )


def _container_path(value: object, context: str) -> str:
    path = _string(value, context)
    parts = path.split("/")
    if (
        len(path) > MAX_CONTAINER_PATH_LENGTH
        or not path.isascii()
        or not path.isprintable()
        or not path.startswith("/")
        or path == "/"
        or "," in path
        or "\\" in path
        or any(part in {"", ".", ".."} for part in parts[1:])
        or str(PurePosixPath(path)) != path
    ):
        raise IntegrityError(f"{context} must be a safe absolute normalized container path")
    return path


@dataclass(frozen=True)
class EphemeralMount:
    name: str
    container_path: str
    size_mb: int

    @classmethod
    def parse(cls, value: object, context: str) -> EphemeralMount:
        data = _mapping(value, context)
        _require_exact(data, {"name", "container_path", "size_mb"}, context)
        name = _string(data["name"], f"{context}.name")
        if EPHEMERAL_NAME.fullmatch(name) is None:
            raise IntegrityError(
                f"{context}.name must be a stable lowercase ephemeral storage name"
            )
        size_mb = data["size_mb"]
        if (
            not isinstance(size_mb, int)
            or isinstance(size_mb, bool)
            or not 1 <= size_mb <= MAX_EPHEMERAL_SIZE_MB
        ):
            raise IntegrityError(f"{context}.size_mb must be between 1 and {MAX_EPHEMERAL_SIZE_MB}")
        return cls(
            name, _container_path(data["container_path"], f"{context}.container_path"), size_mb
        )


@dataclass(frozen=True)
class EphemeralStorage:
    uid: int
    gid: int
    seeded: tuple[EphemeralMount, ...]
    empty: tuple[EphemeralMount, ...]

    @classmethod
    def parse(cls, value: object) -> EphemeralStorage:
        data = _mapping(value, "ephemeral_storage")
        _require_exact(data, {"uid", "gid", "seeded", "empty"}, "ephemeral_storage")
        identifiers: dict[str, int] = {}
        for key in ("uid", "gid"):
            identifier = data[key]
            if (
                not isinstance(identifier, int)
                or isinstance(identifier, bool)
                or not 0 <= identifier <= 65_535
            ):
                raise IntegrityError(f"ephemeral_storage.{key} must be between 0 and 65535")
            identifiers[key] = identifier

        groups: dict[str, tuple[EphemeralMount, ...]] = {}
        for key in ("seeded", "empty"):
            values = _sequence(data[key], f"ephemeral_storage.{key}")
            if len(values) > MAX_EPHEMERAL_MOUNTS:
                raise IntegrityError(
                    f"ephemeral_storage.{key} exceeds the {MAX_EPHEMERAL_MOUNTS}-mount limit"
                )
            groups[key] = tuple(
                EphemeralMount.parse(item, f"ephemeral_storage.{key}[{index}]")
                for index, item in enumerate(values)
            )

        mounts = groups["seeded"] + groups["empty"]
        names = [mount.name for mount in mounts]
        if len(names) != len(set(names)):
            raise IntegrityError(
                "ephemeral_storage seeded and empty mount names must be unique and disjoint"
            )
        paths = [mount.container_path for mount in mounts]
        if len(paths) != len(set(paths)):
            raise IntegrityError("ephemeral_storage container paths must be unique")
        parsed_paths = [PurePosixPath(path) for path in paths]
        if any(
            left in right.parents or right in left.parents
            for index, left in enumerate(parsed_paths)
            for right in parsed_paths[index + 1 :]
        ):
            raise IntegrityError("ephemeral_storage container paths must not overlap")
        if sum(mount.size_mb for mount in mounts) > MAX_EPHEMERAL_TOTAL_MB:
            raise IntegrityError(
                f"ephemeral_storage exceeds the {MAX_EPHEMERAL_TOTAL_MB} MiB aggregate limit"
            )
        return cls(identifiers["uid"], identifiers["gid"], groups["seeded"], groups["empty"])


MANIFEST_KEYS = {
    "schema_version",
    "id",
    "display_name",
    "description",
    "categories",
    "runtime_backend",
    "upstream",
    "version",
    "license",
    "trust",
    "images",
    "services",
    "friendly_hostname",
    "health_check",
    "initialization",
    "reset",
    "default_credentials",
    "resources",
    "ephemeral_storage",
    "persistence",
    "outbound_network",
    "dangerous_capabilities",
    "expected_functionality",
    "known_limitations",
    "last_verified",
    "adapter_status",
    "verification",
    "taxonomy",
    "references",
}


@dataclass(frozen=True)
class Manifest:
    raw: dict[str, Any]
    id: str
    display_name: str
    description: str
    categories: tuple[str, ...]
    runtime_backend: str
    trust: TrustLevel
    adapter_status: AdapterStatus
    images: tuple[Image, ...]
    services: tuple[Service, ...]
    ephemeral_storage: EphemeralStorage
    persistence_required: bool
    persistence_volumes: tuple[str, ...]
    friendly_hostname: str
    outbound_required: bool
    status_reason: str
    version_release: str
    version_tag: str
    version_commit: str
    trust_evidence: tuple[str, ...]
    trust_limitations: tuple[str, ...]
    verification_platforms: tuple[str, ...]
    verification_evidence: tuple[str, ...]
    last_verified: date

    @classmethod
    def parse(cls, value: object) -> Manifest:
        data = _mapping(value, "manifest")
        _require_exact(data, MANIFEST_KEYS, "manifest")
        if data["schema_version"] != 1:
            raise IntegrityError("unsupported manifest schema_version")
        lab_id = _string(data["id"], "id")
        if not LAB_ID.fullmatch(lab_id):
            raise IntegrityError("invalid stable lab id")
        if data["runtime_backend"] != "docker-engine":
            raise IntegrityError("runtime_backend must be docker-engine")
        hostname = _string(data["friendly_hostname"], "friendly_hostname")
        if not HOSTNAME.fullmatch(hostname):
            raise IntegrityError("friendly_hostname must use the reserved .test domain")
        upstream = _mapping(data["upstream"], "upstream")
        _require_exact(upstream, {"repository", "homepage"}, "upstream")
        for key in ("repository", "homepage"):
            url = urlparse(_string(upstream[key], f"upstream.{key}"))
            if url.scheme != "https" or not url.netloc:
                raise IntegrityError(f"upstream.{key} must be an https URL")
        version = _mapping(data["version"], "version")
        _require_exact(version, {"release", "tag", "commit"}, "version")
        version_release = _string(version["release"], "version.release")
        version_tag = _string(version["tag"], "version.tag")
        commit = _string(version["commit"], "version.commit", allow_empty=True)
        if commit and not COMMIT.fullmatch(commit):
            raise IntegrityError("version.commit must be a full lowercase commit SHA")
        license_data = _mapping(data["license"], "license")
        _require_exact(license_data, {"spdx", "evidence_url", "redistribution"}, "license")
        _string(license_data["spdx"], "license.spdx")
        _string(license_data["redistribution"], "license.redistribution")
        evidence = urlparse(_string(license_data["evidence_url"], "license.evidence_url"))
        if evidence.scheme != "https" or not evidence.netloc:
            raise IntegrityError("license evidence must be an https URL")
        trust_data = _mapping(data["trust"], "trust")
        _require_exact(trust_data, {"level", "evidence", "limitations", "status_reason"}, "trust")
        try:
            trust = TrustLevel(_string(trust_data["level"], "trust.level"))
        except ValueError as exc:
            raise IntegrityError("trust.level is not supported") from exc
        trust_evidence = _https_list(trust_data["evidence"], "trust.evidence")
        trust_limitations = _string_list(trust_data["limitations"], "trust.limitations")
        try:
            status = AdapterStatus(_string(data["adapter_status"], "adapter_status"))
        except ValueError as exc:
            raise IntegrityError("adapter_status is not supported") from exc
        status_reason = _string(trust_data["status_reason"], "trust.status_reason")
        images = tuple(Image.parse(item) for item in _sequence(data["images"], "images"))
        services = tuple(Service.parse(item) for item in _sequence(data["services"], "services"))
        image_roles = [image.role for image in images]
        if len(image_roles) != len(set(image_roles)):
            raise IntegrityError("image roles must be unique")
        if status is AdapterStatus.RUNNABLE:
            if trust is TrustLevel.QUARANTINED:
                raise IntegrityError("a runnable adapter cannot be quarantined")
            if (
                not images
                or not services
                or any(not image.digest or not image.architectures for image in images)
            ):
                raise IntegrityError(
                    "a runnable adapter needs services and architecture-qualified digest-pinned "
                    "images"
                )
            if not commit:
                raise IntegrityError("a runnable adapter requires a pinned upstream commit")
            if not trust_evidence:
                raise IntegrityError("a runnable adapter requires trust evidence")
            if version_tag.casefold() == "latest":
                raise IntegrityError("a runnable adapter cannot use the latest tag")
            if trust is TrustLevel.UPSTREAM_PINNED and not trust_limitations:
                raise IntegrityError(
                    "upstream-pinned trust must disclose its provenance limitation"
                )
            if len(images) != 2 or set(image_roles) != {"application", "gateway"}:
                raise IntegrityError(
                    "a runnable Docker Engine adapter requires exactly one application and one "
                    "gateway image"
                )
            service_names = [service.name for service in services]
            if len(service_names) != len(set(service_names)):
                raise IntegrityError("runnable service names must be unique")
            if any(
                service.image_role != "application" or service.protocol != "http"
                for service in services
            ):
                raise IntegrityError(
                    "current runnable adapters support HTTP application health services only"
                )
            if len({service.internal_port for service in services}) != 1:
                raise IntegrityError(
                    "current runnable adapter health services must share one internal port"
                )
        elif trust is not TrustLevel.QUARANTINED:
            raise IntegrityError("a non-runnable adapter must use quarantined trust")
        elif not trust_limitations:
            raise IntegrityError("quarantined trust must record its unresolved limitation")
        roles = {image.role for image in images}
        if status is AdapterStatus.RUNNABLE and any(
            service.image_role not in roles for service in services
        ):
            raise IntegrityError("service references an unknown image role")
        outbound = _mapping(data["outbound_network"], "outbound_network")
        _require_exact(
            outbound, {"required", "reason", "challenge_dependencies"}, "outbound_network"
        )
        if not isinstance(outbound["required"], bool):
            raise IntegrityError("outbound_network.required must be boolean")
        _string(outbound["reason"], "outbound_network.reason")
        _string_list(outbound["challenge_dependencies"], "outbound_network.challenge_dependencies")

        health = _mapping(data["health_check"], "health_check")
        _require_exact(health, {"type", "checks", "timeout_seconds"}, "health_check")
        health_type = _string(health["type"], "health_check.type")
        _string_list(health["checks"], "health_check.checks")
        health_timeout = health["timeout_seconds"]
        if (
            not isinstance(health_timeout, int)
            or isinstance(health_timeout, bool)
            or not 1 <= health_timeout <= 900
        ):
            raise IntegrityError("health_check.timeout_seconds must be between 1 and 900")
        if status is AdapterStatus.RUNNABLE and health_type != "http-identity-and-functionality":
            raise IntegrityError(
                "current runnable adapters require http-identity-and-functionality health checks"
            )

        initialization = _mapping(data["initialization"], "initialization")
        _require_exact(initialization, {"automatic", "steps"}, "initialization")
        if not isinstance(initialization["automatic"], bool):
            raise IntegrityError("initialization.automatic must be boolean")
        _string_list(initialization["steps"], "initialization.steps")
        if status is AdapterStatus.RUNNABLE and not initialization["automatic"]:
            raise IntegrityError("current runnable adapters require automatic initialization")

        reset = _mapping(data["reset"], "reset")
        _require_exact(reset, {"strategy", "effects"}, "reset")
        _string(reset["strategy"], "reset.strategy")
        _string_list(reset["effects"], "reset.effects")

        resource_data = _mapping(data["resources"], "resources")
        _require_exact(resource_data, {"memory_mb", "cpus", "pids", "read_only_root"}, "resources")
        memory = resource_data["memory_mb"]
        cpus = resource_data["cpus"]
        pids = resource_data["pids"]
        if not isinstance(memory, int) or isinstance(memory, bool) or not 128 <= memory <= 16_384:
            raise IntegrityError("resources.memory_mb is outside the supported range")
        if not isinstance(cpus, int | float) or isinstance(cpus, bool) or not 0.1 <= cpus <= 8:
            raise IntegrityError("resources.cpus is outside the supported range")
        if not isinstance(pids, int) or isinstance(pids, bool) or not 16 <= pids <= 4_096:
            raise IntegrityError("resources.pids is outside the supported range")
        if not isinstance(resource_data["read_only_root"], bool):
            raise IntegrityError("resources.read_only_root must be boolean")
        if status is AdapterStatus.RUNNABLE and not resource_data["read_only_root"]:
            raise IntegrityError("current runnable adapters require a read-only root filesystem")

        ephemeral_storage = EphemeralStorage.parse(data["ephemeral_storage"])

        persistence = _mapping(data["persistence"], "persistence")
        _require_exact(persistence, {"required", "volumes"}, "persistence")
        if not isinstance(persistence["required"], bool):
            raise IntegrityError("persistence.required must be boolean")
        persistence_volumes = _string_list(persistence["volumes"], "persistence.volumes")
        if len(persistence_volumes) != len(set(persistence_volumes)):
            raise IntegrityError("persistence.volumes must be unique")
        if status is AdapterStatus.RUNNABLE:
            if ephemeral_storage.uid == 0 or ephemeral_storage.gid == 0:
                raise IntegrityError(
                    "runnable application storage uid and gid must both be non-zero"
                )
            scratch_names = {
                mount.name for mount in ephemeral_storage.seeded + ephemeral_storage.empty
            }
            if set(persistence_volumes) != scratch_names:
                raise IntegrityError(
                    "runnable persistence.volumes must exactly identify declared writable storage"
                )
            if persistence["required"] and not scratch_names:
                raise IntegrityError(
                    "persistent runnable adapters require at least one declared writable mount"
                )

        verification = _mapping(data["verification"], "verification")
        _require_exact(verification, {"status", "platforms", "evidence"}, "verification")
        verification_status = _string(verification["status"], "verification.status")
        if verification_status not in {"passed", "blocked"}:
            raise IntegrityError("verification.status must be passed or blocked")
        verified_platforms = _platform_list(verification["platforms"], "verification.platforms")
        verification_evidence = _string_list(verification["evidence"], "verification.evidence")
        if status is AdapterStatus.RUNNABLE and (
            verification_status != "passed" or not verified_platforms or not verification_evidence
        ):
            raise IntegrityError("a runnable adapter requires recorded smoke-test evidence")
        if status is not AdapterStatus.RUNNABLE and verification_status != "blocked":
            raise IntegrityError("a non-runnable adapter verification must be blocked")

        taxonomy = _mapping(data["taxonomy"], "taxonomy")
        _require_exact(taxonomy, {"owasp", "cwe", "cve"}, "taxonomy")
        for key in ("owasp", "cwe", "cve"):
            _string_list(taxonomy[key], f"taxonomy.{key}")
        for key in (
            "categories",
            "default_credentials",
            "dangerous_capabilities",
            "expected_functionality",
            "known_limitations",
            "references",
        ):
            _string_list(data[key], key)
        last_verified = _date(data["last_verified"], "last_verified")
        return cls(
            raw=data,
            id=lab_id,
            display_name=_string(data["display_name"], "display_name"),
            description=_string(data["description"], "description"),
            categories=_string_list(data["categories"], "categories"),
            runtime_backend="docker-engine",
            trust=trust,
            adapter_status=status,
            images=images,
            services=services,
            ephemeral_storage=ephemeral_storage,
            persistence_required=persistence["required"],
            persistence_volumes=persistence_volumes,
            friendly_hostname=hostname,
            outbound_required=outbound["required"],
            status_reason=status_reason,
            version_release=version_release,
            version_tag=version_tag,
            version_commit=commit,
            trust_evidence=trust_evidence,
            trust_limitations=trust_limitations,
            verification_platforms=verified_platforms,
            verification_evidence=verification_evidence,
            last_verified=last_verified,
        )


LOCK_KEYS = {
    "schema_version",
    "lab_id",
    "lab_version",
    "upstream_release",
    "upstream_commit",
    "images",
    "template_sha256",
    "source_sha256",
    "build_recipe_revision",
    "sbom_url",
    "provenance_url",
    "signature_url",
    "redistribution_status",
    "redistribution_evidence_url",
    "trust_evidence",
    "verified_at",
    "verified_platforms",
    "verification_evidence",
}


@dataclass(frozen=True)
class Lockfile:
    raw: dict[str, Any]
    lab_id: str
    images: tuple[Image, ...]
    lab_version: str
    upstream_release: str
    upstream_commit: str
    template_sha256: str
    source_sha256: str
    build_recipe_revision: str
    sbom_url: str
    provenance_url: str
    signature_url: str
    redistribution_status: str
    redistribution_evidence_url: str
    trust_evidence: tuple[str, ...]
    verified_at: datetime
    verified_platforms: tuple[str, ...]
    verification_evidence: tuple[str, ...]

    @classmethod
    def parse(cls, value: object) -> Lockfile:
        data = _mapping(value, "lockfile")
        _require_exact(data, LOCK_KEYS, "lockfile")
        if data["schema_version"] != 1:
            raise IntegrityError("unsupported lockfile schema_version")
        lab_id = _string(data["lab_id"], "lab_id")
        if not LAB_ID.fullmatch(lab_id):
            raise IntegrityError("invalid lockfile lab_id")
        images = tuple(Image.parse(item) for item in _sequence(data["images"], "images"))
        roles = [image.role for image in images]
        if len(roles) != len(set(roles)):
            raise IntegrityError("lockfile image roles must be unique")
        for image in images:
            if not image.digest:
                raise IntegrityError("lockfile images must have immutable digests")
        checksums: dict[str, str] = {}
        for key in ("template_sha256", "source_sha256"):
            digest = _string(data[key], key, allow_empty=True)
            if digest and not DIGEST.fullmatch(digest):
                raise IntegrityError(f"{key} must be an sha256 digest")
            checksums[key] = digest
        commit = _string(data["upstream_commit"], "upstream_commit", allow_empty=True)
        if commit and not COMMIT.fullmatch(commit):
            raise IntegrityError("lockfile upstream_commit must be a full SHA")
        lab_version = _string(data["lab_version"], "lab_version")
        upstream_release = _string(data["upstream_release"], "upstream_release")
        build_recipe_revision = _string(
            data["build_recipe_revision"], "build_recipe_revision", allow_empty=True
        )
        evidence_urls: dict[str, str] = {}
        for key in (
            "sbom_url",
            "provenance_url",
            "signature_url",
            "redistribution_evidence_url",
        ):
            value = _string(data[key], key, allow_empty=True)
            if value:
                parsed = urlparse(value)
                if parsed.scheme != "https" or not parsed.netloc:
                    raise IntegrityError(f"{key} must be empty or an https URL")
            evidence_urls[key] = value
        redistribution_status = _string(data["redistribution_status"], "redistribution_status")
        if redistribution_status not in {
            "not-applicable",
            "unresolved",
            "permitted",
            "prohibited",
        }:
            raise IntegrityError("redistribution_status is not supported")
        if (
            redistribution_status in {"permitted", "prohibited"}
            and not evidence_urls["redistribution_evidence_url"]
        ):
            raise IntegrityError("a resolved redistribution status requires immutable evidence")
        trust_evidence = _https_list(data["trust_evidence"], "trust_evidence")
        if not trust_evidence:
            raise IntegrityError("trust_evidence must not be empty")
        verified_platforms = _platform_list(data["verified_platforms"], "verified_platforms")
        verification_evidence = _string_list(data["verification_evidence"], "verification_evidence")
        verified_at = _utc_timestamp(data["verified_at"], "verified_at")
        return cls(
            data,
            lab_id,
            images,
            lab_version,
            upstream_release,
            commit,
            checksums["template_sha256"],
            checksums["source_sha256"],
            build_recipe_revision,
            evidence_urls["sbom_url"],
            evidence_urls["provenance_url"],
            evidence_urls["signature_url"],
            redistribution_status,
            evidence_urls["redistribution_evidence_url"],
            trust_evidence,
            verified_at,
            verified_platforms,
            verification_evidence,
        )

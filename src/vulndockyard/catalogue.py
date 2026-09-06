"""Read-only packaged catalogue and immutable lock access."""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from .errors import IntegrityError, NotFoundError
from .jsonio import StrictJSONError, strict_json_loads
from .models import AdapterStatus, Lockfile, Manifest, TrustLevel


def canonical_json(data: object) -> bytes:
    return (
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()


def identity(data: object) -> str:
    return hashlib.sha256(canonical_json(data)).hexdigest()


def template_identity(manifest: Manifest) -> str:
    """Bind the controller-rendered orchestration inputs into an immutable lock digest."""
    keys = (
        "runtime_backend",
        "images",
        "services",
        "friendly_hostname",
        "health_check",
        "initialization",
        "reset",
        "resources",
        "ephemeral_storage",
        "persistence",
        "outbound_network",
        "dangerous_capabilities",
    )
    template = {key: manifest.raw[key] for key in keys}
    return f"sha256:{hashlib.sha256(canonical_json(template)).hexdigest()}"


@dataclass(frozen=True)
class ReviewedLab:
    manifest: Manifest
    lock: Lockfile
    manifest_identity: str


class Catalogue:
    def __init__(self, root: Path | None = None) -> None:
        self._root = root

    def _directory(self, name: str) -> Any:  # importlib Traversable has no stable narrow protocol
        if self._root is not None:
            return self._root / name
        return resources.files("vulndockyard").joinpath("data", name)

    @staticmethod
    def _load(path: Any) -> object:
        try:
            if isinstance(path, Path):
                info = path.lstat()
                if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                    raise IntegrityError(f"reviewed data is not a regular file: {path}")
            content = path.read_bytes()
            if len(content) > 2_000_000 or b"\x00" in content:
                raise IntegrityError(f"reviewed data is oversized or contains NUL: {path}")
            return strict_json_loads(content)
        except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError) as exc:
            raise IntegrityError(f"cannot load reviewed data {path}: {exc}") from exc

    @staticmethod
    def _validate_runnable_binding(manifest: Manifest, lock: Lockfile) -> None:
        if manifest.images != lock.images:
            raise IntegrityError(f"manifest and lock images differ for {manifest.id}")
        if (
            manifest.version_release != lock.lab_version
            or manifest.version_tag != lock.upstream_release
            or manifest.version_commit != lock.upstream_commit
        ):
            raise IntegrityError(f"manifest and lock versions differ for {manifest.id}")
        if manifest.trust_evidence != lock.trust_evidence:
            raise IntegrityError(f"manifest and lock trust evidence differ for {manifest.id}")
        if manifest.verification_platforms != lock.verified_platforms:
            raise IntegrityError(f"manifest and lock verified platforms differ for {manifest.id}")
        if manifest.last_verified != lock.verified_at.date():
            raise IntegrityError(f"manifest and lock verification dates differ for {manifest.id}")
        if lock.template_sha256 != template_identity(manifest):
            raise IntegrityError(
                f"manifest orchestration template differs from lock for {manifest.id}"
            )
        if manifest.trust is TrustLevel.VULNDOCKYARD_BUILT:
            if not lock.source_sha256 or not lock.build_recipe_revision:
                raise IntegrityError(
                    "vulndockyard-built lock lacks source or build-recipe evidence for "
                    f"{manifest.id}"
                )
            application_images = tuple(
                image for image in manifest.images if image.role == "application"
            )
            if not application_images or any(
                not image.name.startswith("ghcr.io/") for image in application_images
            ):
                raise IntegrityError(
                    f"vulndockyard-built application image is not hosted on GHCR for {manifest.id}"
                )

    def all(self) -> tuple[ReviewedLab, ...]:
        manifest_dir = self._directory("manifests")
        lock_dir = self._directory("locks")
        labs: list[ReviewedLab] = []
        manifest_paths = tuple(
            path
            for path in sorted(manifest_dir.iterdir(), key=lambda item: item.name)
            if path.name.endswith(".json")
        )
        for path in manifest_paths:
            manifest_value = self._load(path)
            manifest = Manifest.parse(manifest_value)
            if path.name != f"{manifest.id}.json":
                raise IntegrityError(f"manifest filename does not match its lab id: {path.name}")
            lock_path = lock_dir.joinpath(f"{manifest.id}.lock.json")
            lock = Lockfile.parse(self._load(lock_path))
            if lock.lab_id != manifest.id:
                raise IntegrityError(f"lockfile lab mismatch for {manifest.id}")
            if manifest.adapter_status is AdapterStatus.RUNNABLE:
                self._validate_runnable_binding(manifest, lock)
            labs.append(ReviewedLab(manifest, lock, identity(manifest.raw)))
        ids = [lab.manifest.id for lab in labs]
        if len(ids) != len(set(ids)):
            raise IntegrityError("catalogue contains duplicate lab ids")
        hostnames = [lab.manifest.friendly_hostname for lab in labs]
        if len(hostnames) != len(set(hostnames)):
            raise IntegrityError("catalogue contains duplicate friendly hostnames")
        expected_locks = {f"{lab.manifest.id}.lock.json" for lab in labs}
        actual_locks = {
            path.name for path in lock_dir.iterdir() if path.name.endswith(".lock.json")
        }
        if actual_locks != expected_locks:
            raise IntegrityError("catalogue manifest and lockfile inventories differ")
        return tuple(labs)

    def get(self, query: str) -> ReviewedLab:
        normalized = query.casefold()
        exact = [lab for lab in self.all() if lab.manifest.id.casefold() == normalized]
        if exact:
            return exact[0]
        matches = [
            lab
            for lab in self.all()
            if normalized in lab.manifest.id.casefold()
            or normalized in lab.manifest.display_name.casefold()
        ]
        if not matches:
            raise NotFoundError(f"unknown lab: {query}")
        if len(matches) > 1:
            names = ", ".join(lab.manifest.id for lab in matches)
            raise NotFoundError(f"ambiguous lab {query!r}; matches: {names}")
        return matches[0]

    def search(self, query: str) -> tuple[ReviewedLab, ...]:
        term = query.casefold()
        return tuple(
            lab
            for lab in self.all()
            if term in canonical_json(lab.manifest.raw).decode().casefold()
        )

    def validate(self) -> tuple[ReviewedLab, ...]:
        return self.all()

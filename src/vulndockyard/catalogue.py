"""Read-only packaged catalogue and immutable lock access."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from .errors import IntegrityError, NotFoundError
from .models import Lockfile, Manifest


def canonical_json(data: object) -> bytes:
    return (
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()


def identity(data: object) -> str:
    return hashlib.sha256(canonical_json(data)).hexdigest()


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
            text = path.read_text(encoding="utf-8")
            return json.loads(text)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise IntegrityError(f"cannot load reviewed data {path}: {exc}") from exc

    def all(self) -> tuple[ReviewedLab, ...]:
        manifest_dir = self._directory("manifests")
        labs: list[ReviewedLab] = []
        for path in sorted(manifest_dir.iterdir(), key=lambda item: item.name):
            if not path.name.endswith(".json"):
                continue
            manifest_value = self._load(path)
            manifest = Manifest.parse(manifest_value)
            lock_path = self._directory("locks").joinpath(f"{manifest.id}.lock.json")
            lock = Lockfile.parse(self._load(lock_path))
            if lock.lab_id != manifest.id:
                raise IntegrityError(f"lockfile lab mismatch for {manifest.id}")
            if manifest.adapter_status.value == "runnable":
                manifest_refs = {
                    (image.role, image.name, image.digest) for image in manifest.images
                }
                lock_refs = {(image.role, image.name, image.digest) for image in lock.images}
                if manifest_refs != lock_refs:
                    raise IntegrityError(f"manifest and lock images differ for {manifest.id}")
            labs.append(ReviewedLab(manifest, lock, identity(manifest.raw)))
        ids = [lab.manifest.id for lab in labs]
        if len(ids) != len(set(ids)):
            raise IntegrityError("catalogue contains duplicate lab ids")
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

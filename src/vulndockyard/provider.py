"""Pinned, verified, searchable Vulhub provider cache."""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any, cast

from .compose_policy import load_compose, validate_compose
from .errors import IntegrityError, PolicyError, PreflightError
from .paths import Paths, remove_owned_tree

CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass(frozen=True)
class ProviderLock:
    repository: str
    commit: str
    archive_url: str
    archive_sha256: str
    license: str


@dataclass(frozen=True)
class ProviderEntry:
    path: str
    product: str
    category: str
    cves: tuple[str, ...]
    status: str
    reasons: tuple[str, ...]


def _load_resource(name: str) -> object:
    path = resources.files("vulndockyard").joinpath("data", "providers", name)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"provider metadata is invalid: {name}") from exc


def load_provider_lock() -> ProviderLock:
    value = _load_resource("vulhub.lock.json")
    if not isinstance(value, dict):
        raise IntegrityError("Vulhub provider lock is malformed")
    keys = {"repository", "commit", "archive_url", "archive_sha256", "license"}
    if value.keys() != keys or any(not isinstance(value[key], str) for key in keys):
        raise IntegrityError("Vulhub provider lock has missing or unknown fields")
    result = ProviderLock(**cast(dict[str, str], value))
    if not re.fullmatch(r"[0-9a-f]{40}", result.commit):
        raise IntegrityError("Vulhub commit must be a full SHA")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", result.archive_sha256):
        raise IntegrityError("Vulhub archive checksum must be pinned")
    return result


class VulhubProvider:
    def __init__(self, paths: Paths | None = None) -> None:
        self.paths = paths or Paths.discover()
        self.root = self.paths.cache / "providers" / "vulhub"
        self.index_path = self.root / "index.json"

    def _allowlist(self) -> dict[str, dict[str, Any]]:
        value = _load_resource("vulhub-allowlist.json")
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, dict) for key, item in value.items()
        ):
            raise IntegrityError("Vulhub allowlist is malformed")
        return cast(dict[str, dict[str, Any]], value)

    @staticmethod
    def _extract(archive: bytes, destination: Path, commit: str) -> Path:
        total = 0
        members_count = 0
        try:
            bundle = tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz")  # noqa: SIM115
        except tarfile.TarError as exc:
            raise IntegrityError("Vulhub archive is not a valid gzip tar") from exc
        with bundle:
            members = bundle.getmembers()
            names: set[str] = set()
            for member in members:
                members_count += 1
                total += max(member.size, 0)
                path = PurePosixPath(member.name)
                if (
                    members_count > 25_000
                    or total > 250_000_000
                    or path.is_absolute()
                    or ".." in path.parts
                    or member.issym()
                    or member.islnk()
                    or member.isdev()
                    or member.name in names
                ):
                    raise IntegrityError(f"unsafe Vulhub archive member: {member.name}")
                names.add(member.name)
            for member in members:
                relative = PurePosixPath(member.name)
                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise IntegrityError(f"unsupported Vulhub archive member: {member.name}")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise IntegrityError(f"could not read Vulhub archive member: {member.name}")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o600)
        roots = [path for path in destination.iterdir() if path.is_dir()]
        if len(roots) != 1 or not roots[0].name.endswith(commit):
            raise IntegrityError("Vulhub archive root does not match the pinned commit")
        return roots[0]

    def sync(self, *, timeout: float = 60) -> tuple[ProviderEntry, ...]:
        lock = load_provider_lock()
        if lock.repository != "https://github.com/vulhub/vulhub" or not lock.archive_url.startswith(
            "https://github.com/vulhub/vulhub/archive/"
        ):
            raise IntegrityError("Vulhub provider lock uses an unauthorized origin")
        request = urllib.request.Request(  # noqa: S310 - exact HTTPS origin checked above
            lock.archive_url, headers={"User-Agent": "VulnDockyard/1"}
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - exact HTTPS origin checked above
                request, timeout=timeout
            ) as response:
                archive = response.read(300_000_001)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise PreflightError(f"could not retrieve pinned Vulhub metadata: {exc}") from exc
        if len(archive) > 300_000_000:
            raise IntegrityError("Vulhub archive exceeds 300 MB")
        actual = f"sha256:{hashlib.sha256(archive).hexdigest()}"
        if actual != lock.archive_sha256:
            raise IntegrityError(
                f"Vulhub archive checksum mismatch: expected {lock.archive_sha256}, got {actual}"
            )
        self.root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=".vulhub-", dir=self.root.parent))
        previous = self.root.with_name("vulhub.previous")
        backed_up = False
        activated = False
        try:
            source = self._extract(archive, temporary, lock.commit)
            entries = self._index(source)
            final = temporary / "verified"
            source.rename(final)
            index_bytes = (
                json.dumps(
                    [asdict(entry) for entry in entries], sort_keys=True, separators=(",", ":")
                )
                + "\n"
            ).encode()
            (temporary / "index.json").write_bytes(index_bytes)
            (temporary / "integrity.json").write_text(
                json.dumps(
                    {
                        "commit": lock.commit,
                        "archive_sha256": actual,
                        "index_sha256": f"sha256:{hashlib.sha256(index_bytes).hexdigest()}",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            if previous.exists():
                remove_owned_tree(previous, self.root.parent)
            if self.root.exists():
                self.root.rename(previous)
                backed_up = True
            temporary.rename(self.root)
            activated = True
            self.root.chmod(0o700)
            for metadata_file in (self.index_path, self.root / "integrity.json"):
                metadata_file.chmod(0o600)
            if previous.exists():
                remove_owned_tree(previous, self.root.parent)
        except BaseException:
            if activated and self.root.exists():
                remove_owned_tree(self.root, self.root.parent)
            if backed_up and previous.exists():
                previous.rename(self.root)
            if temporary.exists():
                remove_owned_tree(temporary, self.root.parent)
            raise
        return entries

    def _index(self, source: Path) -> tuple[ProviderEntry, ...]:
        allowlist = self._allowlist()
        metadata_path = source / "environments.toml"
        try:
            if metadata_path.stat().st_size > 10_000_000:
                raise IntegrityError("Vulhub environments.toml exceeds 10 MB")
            metadata_value = tomllib.loads(metadata_path.read_text(encoding="utf-8"))
            environment_values = metadata_value["environment"]
        except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
            raise IntegrityError("Vulhub environments.toml is malformed") from exc
        if not isinstance(environment_values, list):
            raise IntegrityError("Vulhub environment metadata must be an array")
        metadata: dict[str, dict[str, Any]] = {}
        for item in environment_values:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise IntegrityError("Vulhub environment metadata entry is malformed")
            metadata[item["path"]] = cast(dict[str, Any], item)
        entries: list[ProviderEntry] = []
        names = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
        compose_files = sorted(path for name in names for path in source.rglob(name))
        for compose_path in compose_files:
            relative = compose_path.parent.relative_to(source).as_posix()
            parts = relative.split("/")
            category = parts[0] if parts else "unknown"
            product = parts[-2] if len(parts) > 1 and CVE.fullmatch(parts[-1]) else parts[-1]
            cves = tuple(sorted({value.upper() for value in CVE.findall(relative)}))
            upstream = metadata.get(relative)
            if upstream is not None:
                if isinstance(upstream.get("app"), str):
                    product = upstream["app"]
                upstream_cves = upstream.get("cve", [])
                if isinstance(upstream_cves, list) and all(
                    isinstance(value, str) for value in upstream_cves
                ):
                    cves = tuple(sorted(value.upper() for value in upstream_cves))
                tags = upstream.get("tags", [])
                if isinstance(tags, list) and tags and isinstance(tags[0], str):
                    category = tags[0]
            reasons: list[str] = []
            approved = allowlist.get(relative)
            try:
                document = load_compose(compose_path.read_bytes())
                images = set(approved.get("images", [])) if approved else set()
                commands = set(approved.get("commands", [])) if approved else set()
                review = validate_compose(document, approved_images=images, allow_commands=commands)
                reasons.extend(f"{finding.path}: {finding.reason}" for finding in review.findings)
            except IntegrityError as exc:
                reasons.append(str(exc))
                review = None
            if approved is None:
                reasons.insert(0, "entry is not in the reviewed runnable allowlist")
            status = (
                "runnable"
                if approved is not None and review is not None and review.accepted
                else "blocked"
            )
            entries.append(ProviderEntry(relative, product, category, cves, status, tuple(reasons)))
        return tuple(entries)

    def status(self) -> dict[str, object]:
        lock = load_provider_lock()
        try:
            integrity = json.loads((self.root / "integrity.json").read_text(encoding="utf-8"))
            index_bytes = self.index_path.read_bytes()
            entries = self._parse_entries(index_bytes)
        except (FileNotFoundError, OSError, json.JSONDecodeError, IntegrityError):
            return {
                "provider": "vulhub",
                "state": "not-synced",
                "pinned_commit": lock.commit,
                "entries": 0,
            }
        valid = integrity == {
            "commit": lock.commit,
            "archive_sha256": lock.archive_sha256,
            "index_sha256": f"sha256:{hashlib.sha256(index_bytes).hexdigest()}",
        }
        return {
            "provider": "vulhub",
            "state": "verified" if valid else "stale-or-corrupt",
            "pinned_commit": lock.commit,
            "entries": len(entries),
            "runnable": sum(entry.status == "runnable" for entry in entries),
        }

    def entries(self) -> tuple[ProviderEntry, ...]:
        try:
            lock = load_provider_lock()
            index_bytes = self.index_path.read_bytes()
            integrity = json.loads((self.root / "integrity.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
            raise PolicyError("Vulhub provider is not synced; run provider sync vulhub") from exc
        expected = {
            "commit": lock.commit,
            "archive_sha256": lock.archive_sha256,
            "index_sha256": f"sha256:{hashlib.sha256(index_bytes).hexdigest()}",
        }
        if integrity != expected:
            raise IntegrityError("Vulhub provider cache integrity check failed")
        return self._parse_entries(index_bytes)

    @staticmethod
    def _parse_entries(index_bytes: bytes) -> tuple[ProviderEntry, ...]:
        try:
            value = json.loads(index_bytes)
        except json.JSONDecodeError as exc:
            raise IntegrityError("Vulhub index is malformed") from exc
        if not isinstance(value, list):
            raise IntegrityError("Vulhub index is malformed")
        entries = []
        for item in value:
            if not isinstance(item, dict) or item.keys() != {
                "path",
                "product",
                "category",
                "cves",
                "status",
                "reasons",
            }:
                raise IntegrityError("Vulhub index entry is malformed")
            entries.append(
                ProviderEntry(
                    str(item["path"]),
                    str(item["product"]),
                    str(item["category"]),
                    tuple(str(value) for value in item["cves"]),
                    str(item["status"]),
                    tuple(str(value) for value in item["reasons"]),
                )
            )
        return tuple(entries)

    def search(self, query: str) -> tuple[ProviderEntry, ...]:
        term = query.casefold()
        return tuple(
            entry
            for entry in self.entries()
            if term in json.dumps(asdict(entry), sort_keys=True).casefold()
        )

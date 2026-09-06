"""Pinned, verified, searchable Vulhub provider cache."""

from __future__ import annotations

import hashlib
import io
import json
import math
import re
import shutil
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import date
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any, cast
from urllib.parse import urlparse

from .compose_policy import load_compose, validate_compose
from .errors import IntegrityError, PolicyError, PreflightError
from .jsonio import StrictJSONError, strict_json_loads
from .models import DIGEST, OCI_NAME
from .paths import Paths, remove_owned_tree

CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
PROVIDER_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")


def _image_reference(value: str) -> bool:
    parts = value.rsplit("@", 1)
    return (
        len(parts) == 2
        and OCI_NAME.fullmatch(parts[0]) is not None
        and DIGEST.fullmatch(parts[1]) is not None
    )


def _canonical_provider_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        PROVIDER_PATH.fullmatch(value) is not None
        and not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> urllib.request.Request | None:
        return None


def _open_pinned_archive(request: urllib.request.Request, *, timeout: float) -> Any:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    return opener.open(request, timeout=timeout)


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
        content = path.read_bytes()
        if len(content) > 1_000_000 or b"\x00" in content:
            raise IntegrityError(f"provider metadata is oversized or contains NUL: {name}")
        return strict_json_loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError) as exc:
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
    if (
        result.repository != "https://github.com/vulhub/vulhub"
        or result.archive_url != f"https://codeload.github.com/vulhub/vulhub/tar.gz/{result.commit}"
        or result.license != "MIT"
    ):
        raise IntegrityError("Vulhub provider lock origin or license is unauthorized")
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
        allowlist = cast(dict[str, dict[str, Any]], value)
        lock = load_provider_lock()
        entry_keys = {
            "provider_commit",
            "compose_sha256",
            "images",
            "commands",
            "review",
        }
        review_keys = {
            "status",
            "reviewed_at",
            "reviewer",
            "provenance_evidence",
            "license_evidence",
            "architectures",
            "functionality_evidence",
            "container_escape_exercise",
        }
        for path, item in allowlist.items():
            if not _canonical_provider_path(path):
                raise IntegrityError("Vulhub allowlist path is unsafe")
            if item.keys() != entry_keys or item["provider_commit"] != lock.commit:
                raise IntegrityError(f"Vulhub allowlist entry is malformed or stale: {path}")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", item["compose_sha256"]):
                raise IntegrityError(f"Vulhub allowlist Compose checksum is invalid: {path}")
            images = item["images"]
            commands = item["commands"]
            if (
                not isinstance(images, list)
                or not images
                or not all(isinstance(image, str) and _image_reference(image) for image in images)
                or len(images) != len(set(images))
            ):
                raise IntegrityError(f"Vulhub allowlist images are invalid: {path}")
            if not isinstance(commands, list) or not all(
                isinstance(command, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", command)
                for command in commands
            ):
                raise IntegrityError(f"Vulhub allowlist commands are invalid: {path}")
            review = item["review"]
            if not isinstance(review, dict) or review.keys() != review_keys:
                raise IntegrityError(f"Vulhub allowlist review is malformed: {path}")
            if (
                review["status"] != "runnable"
                or review["container_escape_exercise"] is not False
                or not isinstance(review["reviewed_at"], str)
                or re.fullmatch(r"\d{4}-\d{2}-\d{2}", review["reviewed_at"]) is None
                or not isinstance(review["reviewer"], str)
                or not review["reviewer"].strip()
            ):
                raise IntegrityError(f"Vulhub allowlist review status is invalid: {path}")
            try:
                date.fromisoformat(review["reviewed_at"])
            except ValueError as exc:
                raise IntegrityError(f"Vulhub allowlist review date is invalid: {path}") from exc
            for key in ("provenance_evidence", "license_evidence"):
                evidence = review[key]
                if (
                    not isinstance(evidence, list)
                    or not evidence
                    or not all(
                        isinstance(url, str)
                        and (parsed := urlparse(url)).scheme == "https"
                        and bool(parsed.netloc)
                        for url in evidence
                    )
                ):
                    raise IntegrityError(f"Vulhub allowlist {key} is invalid: {path}")
            architectures = review["architectures"]
            if (
                not isinstance(architectures, list)
                or not architectures
                or not all(
                    architecture in {"linux/amd64", "linux/arm64", "linux/arm/v7"}
                    for architecture in architectures
                )
                or len(architectures) != len(set(architectures))
            ):
                raise IntegrityError(f"Vulhub allowlist architectures are invalid: {path}")
            functionality = review["functionality_evidence"]
            if (
                not isinstance(functionality, list)
                or not functionality
                or not all(
                    isinstance(item, str) and item.isprintable() and 1 <= len(item) <= 240
                    for item in functionality
                )
            ):
                raise IntegrityError(f"Vulhub allowlist functionality evidence is invalid: {path}")
        return allowlist

    @staticmethod
    def _extract(archive: bytes, destination: Path, commit: str) -> Path:
        total = 0
        members_count = 0
        try:
            bundle = tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz")  # noqa: SIM115
        except tarfile.TarError as exc:
            raise IntegrityError("Vulhub archive is not a valid gzip tar") from exc
        with bundle:
            members: list[tarfile.TarInfo] = []
            names: set[str] = set()
            for member in bundle:
                members_count += 1
                total += max(member.size, 0)
                path = PurePosixPath(member.name)
                canonical_name = path.as_posix()
                expected_root = f"vulhub-{commit}"
                if (
                    members_count > 25_000
                    or total > 250_000_000
                    or path.is_absolute()
                    or ".." in path.parts
                    or member.issym()
                    or member.islnk()
                    or member.isdev()
                    or canonical_name in names
                    or len(member.name) > 512
                    or not member.name.isprintable()
                    or "\\" in member.name
                    or not path.parts
                    or path.parts[0] != expected_root
                    or canonical_name != member.name.rstrip("/")
                ):
                    raise IntegrityError(f"unsafe Vulhub archive member: {member.name}")
                names.add(canonical_name)
                members.append(member)
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
        if len(roots) != 1 or roots[0].name != f"vulhub-{commit}":
            raise IntegrityError("Vulhub archive root does not match the pinned commit")
        return roots[0]

    def sync(self, *, timeout: float = 60) -> tuple[ProviderEntry, ...]:
        lock = load_provider_lock()
        expected_archive = f"https://codeload.github.com/vulhub/vulhub/tar.gz/{lock.commit}"
        if (
            lock.repository != "https://github.com/vulhub/vulhub"
            or lock.archive_url != expected_archive
        ):
            raise IntegrityError("Vulhub provider lock uses an unauthorized origin")
        if not math.isfinite(timeout) or not 1 <= timeout <= 300:
            raise PolicyError("provider sync timeout must be between 1 and 300 seconds")
        request = urllib.request.Request(  # noqa: S310 - exact HTTPS origin checked above
            lock.archive_url, headers={"User-Agent": "VulnDockyard/1"}
        )
        try:
            with _open_pinned_archive(request, timeout=timeout) as response:
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
            if item["path"] in metadata:
                raise IntegrityError("Vulhub environment metadata contains a duplicate path")
            metadata[item["path"]] = cast(dict[str, Any], item)
        entries: list[ProviderEntry] = []
        names = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
        compose_files = sorted(path for name in names for path in source.rglob(name))
        compose_directories: set[str] = set()
        for compose_path in compose_files:
            relative = compose_path.parent.relative_to(source).as_posix()
            if not _canonical_provider_path(relative):
                raise IntegrityError(f"Vulhub Compose path is unsafe: {relative!r}")
            if relative in compose_directories:
                raise IntegrityError(f"Vulhub environment has ambiguous Compose files: {relative}")
            compose_directories.add(relative)
            parts = relative.split("/")
            category = parts[0] if parts else "unknown"
            product = parts[-2] if len(parts) > 1 and CVE.fullmatch(parts[-1]) else parts[-1]
            cves = tuple(sorted({value.upper() for value in CVE.findall(relative)}))
            reasons: list[str] = []
            upstream = metadata.get(relative)
            if upstream is not None:
                if isinstance(upstream.get("app"), str):
                    candidate_product = upstream["app"]
                    if candidate_product.isprintable() and 1 <= len(candidate_product) <= 240:
                        product = candidate_product
                    else:
                        reasons.append("environments.toml product metadata is unsafe")
                upstream_cves = upstream.get("cve", [])
                if isinstance(upstream_cves, list) and all(
                    isinstance(value, str) and CVE.fullmatch(value) for value in upstream_cves
                ):
                    cves = tuple(sorted(value.upper() for value in upstream_cves))
                elif upstream_cves:
                    reasons.append("environments.toml CVE metadata is malformed")
                tags = upstream.get("tags", [])
                if isinstance(tags, list) and tags and isinstance(tags[0], str):
                    candidate_category = tags[0]
                    if candidate_category.isprintable() and 1 <= len(candidate_category) <= 240:
                        category = candidate_category
                    else:
                        reasons.append("environments.toml category metadata is unsafe")
            if not product.isprintable() or not 1 <= len(product) <= 240:
                product = parts[-1][:240] or "unknown"
                reasons.append("derived product metadata was unsafe")
            if not category.isprintable() or not 1 <= len(category) <= 240:
                category = "unknown"
                reasons.append("derived category metadata was unsafe")
            approved = allowlist.get(relative)
            try:
                compose_size = compose_path.stat().st_size
            except OSError as exc:
                raise IntegrityError(f"cannot inspect Vulhub Compose for {relative}") from exc
            content = compose_path.read_bytes() if compose_size <= 2_000_000 else b""
            if compose_size > 2_000_000:
                reasons.append("Compose document exceeds 2 MB")
            if approved is not None:
                compose_digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
                if compose_digest != approved["compose_sha256"]:
                    raise IntegrityError(f"reviewed Compose checksum changed for {relative}")
            try:
                if not content:
                    raise IntegrityError("Compose document is empty or exceeds its size bound")
                document = load_compose(content)
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
                if approved is not None and review is not None and review.accepted and not reasons
                else "blocked"
            )
            if any(not reason.isprintable() or len(reason) > 1000 for reason in reasons):
                raise IntegrityError(f"Vulhub rejection reason is unsafe for {relative}")
            entries.append(ProviderEntry(relative, product, category, cves, status, tuple(reasons)))
        missing_reviews = sorted(set(allowlist) - compose_directories)
        if missing_reviews:
            raise IntegrityError(
                "Vulhub allowlist refers to missing environments: " + ", ".join(missing_reviews)
            )
        return tuple(entries)

    def status(self) -> dict[str, object]:
        lock = load_provider_lock()
        try:
            integrity = strict_json_loads(
                (self.root / "integrity.json").read_text(encoding="utf-8")
            )
            index_bytes = self.index_path.read_bytes()
            entries = self._parse_entries(index_bytes)
        except (
            FileNotFoundError,
            OSError,
            json.JSONDecodeError,
            StrictJSONError,
            IntegrityError,
        ):
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
            integrity = strict_json_loads(
                (self.root / "integrity.json").read_text(encoding="utf-8")
            )
        except (FileNotFoundError, OSError, json.JSONDecodeError, StrictJSONError) as exc:
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
            value = strict_json_loads(index_bytes)
        except (json.JSONDecodeError, StrictJSONError) as exc:
            raise IntegrityError("Vulhub index is malformed") from exc
        if not isinstance(value, list):
            raise IntegrityError("Vulhub index is malformed")
        entries = []
        paths: set[str] = set()
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
            path = item["path"]
            product = item["product"]
            category = item["category"]
            cves = item["cves"]
            status = item["status"]
            reasons = item["reasons"]
            if (
                not isinstance(path, str)
                or not _canonical_provider_path(path)
                or not isinstance(product, str)
                or not product.isprintable()
                or not 1 <= len(product) <= 240
                or not isinstance(category, str)
                or not category.isprintable()
                or not 1 <= len(category) <= 240
                or not isinstance(cves, list)
                or not all(isinstance(cve, str) and CVE.fullmatch(cve) for cve in cves)
                or cves != sorted(set(cves))
                or status not in {"blocked", "runnable"}
                or not isinstance(reasons, list)
                or not all(
                    isinstance(reason, str) and reason.isprintable() and len(reason) <= 1000
                    for reason in reasons
                )
                or (status == "runnable" and bool(reasons))
                or (status == "blocked" and not reasons)
                or path in paths
            ):
                raise IntegrityError("Vulhub index entry contains unsafe field values")
            paths.add(path)
            entries.append(
                ProviderEntry(path, product, category, tuple(cves), status, tuple(reasons))
            )
        return tuple(entries)

    def search(self, query: str) -> tuple[ProviderEntry, ...]:
        term = query.casefold()
        return tuple(
            entry
            for entry in self.entries()
            if term in json.dumps(asdict(entry), sort_keys=True).casefold()
        )

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import urllib.request
from pathlib import Path
from types import TracebackType

import pytest

import vulndockyard.provider as provider_module
from vulndockyard.errors import IntegrityError, PolicyError
from vulndockyard.paths import Paths
from vulndockyard.provider import ProviderLock, VulhubProvider, load_provider_lock


def archive(commit: str, *, unsafe: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        root = f"vulhub-{commit}"
        files = {
            f"{root}/environments.toml": (
                b'tags = ["RCE"]\n[[environment]]\nname = "Demo"\n'
                b'cve = ["CVE-2020-0001"]\napp = "Demo Product"\n'
                b'path = "demo/CVE-2020-0001"\ntags = ["RCE"]\n'
            ),
            f"{root}/demo/CVE-2020-0001/docker-compose.yml": (
                b"services:\n  app:\n    image: demo:latest\n"
            ),
        }
        if unsafe:
            files[f"{root}/{unsafe}"] = b"unsafe"
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            bundle.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


class Response(io.BytesIO):
    def __enter__(self) -> Response:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def test_provider_lock_is_exact_and_official() -> None:
    lock = load_provider_lock()
    assert lock.repository == "https://github.com/vulhub/vulhub"
    assert len(lock.commit) == 40
    assert lock.archive_sha256.startswith("sha256:")


def test_verified_sync_indexes_but_does_not_approve(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "a" * 40
    content = archive(commit)
    lock = ProviderLock(
        "https://github.com/vulhub/vulhub",
        commit,
        f"https://github.com/vulhub/vulhub/archive/{commit}.tar.gz",
        "sha256:" + hashlib.sha256(content).hexdigest(),
        "MIT",
    )
    monkeypatch.setattr(provider_module, "load_provider_lock", lambda: lock)
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda request, timeout: Response(content),
    )
    provider = VulhubProvider(xdg_paths)
    entries = provider.sync()
    assert len(entries) == 1
    assert entries[0].path == "demo/CVE-2020-0001"
    assert entries[0].product == "Demo Product"
    assert entries[0].category == "RCE"
    assert entries[0].cves == ("CVE-2020-0001",)
    assert entries[0].status == "blocked"
    assert "not in the reviewed" in entries[0].reasons[0]
    assert provider.status()["state"] == "verified"
    assert provider.search("Demo Product") == entries


def test_provider_cache_tampering_is_detected(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "b" * 40
    content = archive(commit)
    lock = ProviderLock(
        "https://github.com/vulhub/vulhub",
        commit,
        f"https://github.com/vulhub/vulhub/archive/{commit}.tar.gz",
        "sha256:" + hashlib.sha256(content).hexdigest(),
        "MIT",
    )
    monkeypatch.setattr(provider_module, "load_provider_lock", lambda: lock)
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda request, timeout: Response(content),
    )
    provider = VulhubProvider(xdg_paths)
    provider.sync()
    provider.index_path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(IntegrityError, match="integrity"):
        provider.entries()
    assert provider.status()["state"] == "stale-or-corrupt"


def test_provider_rejects_checksum_and_archive_traversal(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    commit = "c" * 40
    content = archive(commit)
    bad_lock = ProviderLock(
        "https://github.com/vulhub/vulhub",
        commit,
        f"https://github.com/vulhub/vulhub/archive/{commit}.tar.gz",
        "sha256:" + "0" * 64,
        "MIT",
    )
    monkeypatch.setattr(provider_module, "load_provider_lock", lambda: bad_lock)
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda request, timeout: Response(content),
    )
    with pytest.raises(IntegrityError, match="checksum mismatch"):
        VulhubProvider(xdg_paths).sync()
    with pytest.raises(IntegrityError, match="unsafe"):
        VulhubProvider._extract(archive(commit, unsafe="../escape"), tmp_path, commit)


def test_provider_absent_and_malformed_cache_are_honest(xdg_paths: Paths) -> None:
    provider = VulhubProvider(xdg_paths)
    assert provider.status()["state"] == "not-synced"
    with pytest.raises(PolicyError, match="not synced"):
        provider.entries()
    provider.root.mkdir(parents=True)
    provider.index_path.write_text("{}", encoding="utf-8")
    lock = load_provider_lock()
    data = provider.index_path.read_bytes()
    (provider.root / "integrity.json").write_text(
        json.dumps(
            {
                "commit": lock.commit,
                "archive_sha256": lock.archive_sha256,
                "index_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(IntegrityError, match="malformed"):
        provider.entries()

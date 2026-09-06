from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tarfile
import threading
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from types import TracebackType
from typing import Any

import pytest

import vulndockyard.provider as provider_module
from vulndockyard.errors import IntegrityError, PolicyError
from vulndockyard.paths import Paths
from vulndockyard.provider import ProviderLock, VulhubProvider, _NoRedirect, load_provider_lock

DIGEST = "sha256:" + "d" * 64


def reviewed_allowlist(commit: str) -> dict[str, object]:
    return {
        "demo/CVE-2020-0001": {
            "provider_commit": commit,
            "compose_sha256": "sha256:" + "c" * 64,
            "images": [f"registry.example.test/demo@{DIGEST}"],
            "commands": [],
            "review": {
                "status": "runnable",
                "reviewed_at": "2026-09-06",
                "reviewer": "VulnDockyard maintainers",
                "provenance_evidence": ["https://example.test/provenance"],
                "license_evidence": ["https://example.test/license"],
                "architectures": ["linux/amd64"],
                "functionality_evidence": ["identity and expected training inventory passed"],
                "container_escape_exercise": False,
            },
        }
    }


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


def duplicate_normalized_archive(commit: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for name in (f"vulhub-{commit}/a//b", f"vulhub-{commit}/a/b"):
            info = tarfile.TarInfo(name)
            info.size = 1
            bundle.addfile(info, io.BytesIO(b"x"))
    return buffer.getvalue()


def unexpected_root_archive(commit: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        info = tarfile.TarInfo("unexpected/file")
        info.size = 1
        bundle.addfile(info, io.BytesIO(b"x"))
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
    assert lock.archive_url == f"https://codeload.github.com/vulhub/vulhub/tar.gz/{lock.commit}"
    assert lock.archive_sha256.startswith("sha256:")


def test_provider_cache_lock_serializes_readers_and_writers(xdg_paths: Paths) -> None:
    provider = VulhubProvider(xdg_paths)
    provider.paths.ensure()
    provider._ensure_private_directory(provider.root.parent)

    with (
        provider._provider_lock(exclusive=True),
        pytest.raises(PolicyError, match="timed out waiting"),
        provider._provider_lock(exclusive=False, timeout=0.1),
    ):
        pytest.fail("a reader acquired an exclusively held provider lock")


def test_provider_public_reader_waits_for_first_sync_activation(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = VulhubProvider(xdg_paths)
    writer_entered = threading.Event()
    release_writer = threading.Event()
    reader_finished = threading.Event()
    failures: list[BaseException] = []
    observed: list[object] = []

    def paused_sync(*, timeout: float) -> tuple[object, ...]:
        del timeout
        writer_entered.set()
        if not release_writer.wait(2):
            raise RuntimeError("test writer release timed out")
        return ()

    def sync() -> None:
        try:
            provider.sync(timeout=2)
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def status() -> None:
        try:
            observed.append(provider.status())
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)
        finally:
            reader_finished.set()

    monkeypatch.setattr(provider, "_sync_unlocked", paused_sync)
    writer = threading.Thread(target=sync)
    reader = threading.Thread(target=status)
    writer.start()
    assert writer_entered.wait(1)
    reader.start()
    assert not reader_finished.wait(0.1)
    release_writer.set()
    writer.join(2)
    reader.join(2)

    assert not writer.is_alive() and not reader.is_alive()
    assert failures == []
    assert observed == [
        {
            "provider": "vulhub",
            "state": "not-synced",
            "pinned_commit": load_provider_lock().commit,
            "entries": 0,
        }
    ]


def test_provider_public_methods_select_the_required_lock_mode(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = VulhubProvider(xdg_paths)
    modes: list[bool] = []

    @contextlib.contextmanager
    def record_lock(*, exclusive: bool, timeout: float = 10) -> Iterator[None]:
        del timeout
        modes.append(exclusive)
        yield

    monkeypatch.setattr(provider, "_provider_lock", record_lock)
    monkeypatch.setattr(provider, "_sync_unlocked", lambda timeout: ())
    provider.sync()
    provider.status()
    with pytest.raises(PolicyError, match="not synced"):
        provider.entries()

    assert modes == [True, False, False]


def test_verified_sync_indexes_but_does_not_approve(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "a" * 40
    content = archive(commit)
    lock = ProviderLock(
        "https://github.com/vulhub/vulhub",
        commit,
        f"https://codeload.github.com/vulhub/vulhub/tar.gz/{commit}",
        "sha256:" + hashlib.sha256(content).hexdigest(),
        "MIT",
    )
    monkeypatch.setattr(provider_module, "load_provider_lock", lambda: lock)
    monkeypatch.setattr(
        provider_module,
        "_open_pinned_archive",
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
        f"https://codeload.github.com/vulhub/vulhub/tar.gz/{commit}",
        "sha256:" + hashlib.sha256(content).hexdigest(),
        "MIT",
    )
    monkeypatch.setattr(provider_module, "load_provider_lock", lambda: lock)
    monkeypatch.setattr(
        provider_module,
        "_open_pinned_archive",
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
        f"https://codeload.github.com/vulhub/vulhub/tar.gz/{commit}",
        "sha256:" + "0" * 64,
        "MIT",
    )
    monkeypatch.setattr(provider_module, "load_provider_lock", lambda: bad_lock)
    monkeypatch.setattr(
        provider_module,
        "_open_pinned_archive",
        lambda request, timeout: Response(content),
    )
    with pytest.raises(IntegrityError, match="checksum mismatch"):
        VulhubProvider(xdg_paths).sync()
    with pytest.raises(IntegrityError, match="unsafe"):
        VulhubProvider._extract(archive(commit, unsafe="../escape"), tmp_path, commit)
    with pytest.raises(IntegrityError, match="unsafe"):
        VulhubProvider._extract(duplicate_normalized_archive(commit), tmp_path, commit)
    with pytest.raises(IntegrityError, match="unsafe"):
        VulhubProvider._extract(unexpected_root_archive(commit), tmp_path, commit)
    with pytest.raises(PolicyError, match="timeout"):
        VulhubProvider(xdg_paths).sync(timeout=float("inf"))


def test_provider_download_redirects_are_disabled() -> None:
    assert (
        _NoRedirect().redirect_request(
            urllib.request.Request("https://github.com/"),
            None,
            302,
            "Found",
            {},
            "http://127.0.0.1/private",
        )
        is None
    )


def test_provider_rejects_even_official_but_redirecting_archive_url(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "3" * 40
    lock = ProviderLock(
        "https://github.com/vulhub/vulhub",
        commit,
        f"https://github.com/vulhub/vulhub/archive/{commit}.tar.gz",
        "sha256:" + "4" * 64,
        "MIT",
    )
    monkeypatch.setattr(provider_module, "load_provider_lock", lambda: lock)
    with pytest.raises(IntegrityError, match="unauthorized origin"):
        VulhubProvider(xdg_paths).sync()


def test_provider_absent_and_malformed_cache_are_honest(xdg_paths: Paths) -> None:
    provider = VulhubProvider(xdg_paths)
    assert provider.status()["state"] == "not-synced"
    with pytest.raises(PolicyError, match="not synced"):
        provider.entries()
    provider.root.mkdir(mode=0o700, parents=True)
    provider.index_path.write_text("{}", encoding="utf-8")
    lock = load_provider_lock()
    data = provider.index_path.read_bytes()
    (provider.root / "integrity.json").write_text(
        json.dumps(
            {
                "commit": lock.commit,
                "archive_sha256": lock.archive_sha256,
                "index_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                "allowlist_sha256": provider._allowlist_sha256(provider._allowlist()),
            }
        ),
        encoding="utf-8",
    )
    provider.index_path.chmod(0o600)
    (provider.root / "integrity.json").chmod(0o600)
    assert provider.status()["state"] == "stale-or-corrupt"
    with pytest.raises(IntegrityError, match="malformed"):
        provider.entries()


def test_provider_cache_rejects_symlinked_or_overpermissive_roots(
    xdg_paths: Paths, tmp_path: Path
) -> None:
    provider = VulhubProvider(xdg_paths)
    provider.root.parent.mkdir(mode=0o700, parents=True)
    target = tmp_path / "foreign-cache"
    target.mkdir()
    provider.root.symlink_to(target, target_is_directory=True)
    assert provider.status()["state"] == "stale-or-corrupt"
    with pytest.raises(IntegrityError, match="unsafe type"):
        provider.entries()

    provider.root.unlink()
    provider.root.mkdir(mode=0o700)
    provider.root.chmod(0o755)
    assert provider.status()["state"] == "stale-or-corrupt"
    with pytest.raises(IntegrityError, match="unsafe type"):
        provider.entries()


def test_cached_runnable_status_cannot_outlive_the_packaged_allowlist(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "7" * 40
    content = archive(commit)
    lock = ProviderLock(
        "https://github.com/vulhub/vulhub",
        commit,
        f"https://codeload.github.com/vulhub/vulhub/tar.gz/{commit}",
        "sha256:" + hashlib.sha256(content).hexdigest(),
        "MIT",
    )
    monkeypatch.setattr(provider_module, "load_provider_lock", lambda: lock)
    monkeypatch.setattr(
        provider_module,
        "_open_pinned_archive",
        lambda request, timeout: Response(content),
    )
    provider = VulhubProvider(xdg_paths)
    provider.sync()
    index = json.loads(provider.index_path.read_text(encoding="utf-8"))
    index[0]["status"] = "runnable"
    index[0]["reasons"] = []
    index_bytes = (json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n").encode()
    provider.index_path.write_bytes(index_bytes)
    (provider.root / "integrity.json").write_text(
        json.dumps(
            {
                "commit": lock.commit,
                "archive_sha256": lock.archive_sha256,
                "index_sha256": "sha256:" + hashlib.sha256(index_bytes).hexdigest(),
                "allowlist_sha256": provider._allowlist_sha256(provider._allowlist()),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )

    assert provider.status()["state"] == "stale-or-corrupt"
    with pytest.raises(IntegrityError, match="reviewed allowlist"):
        provider.entries()


def test_provider_sync_rejects_symlinked_cache_parent_before_network_access(
    xdg_paths: Paths, tmp_path: Path
) -> None:
    xdg_paths.ensure()
    foreign = tmp_path / "foreign-provider-cache"
    foreign.mkdir()
    provider_parent = xdg_paths.cache / "providers"
    provider_parent.symlink_to(foreign, target_is_directory=True)

    with pytest.raises(IntegrityError, match="cache parent"):
        VulhubProvider(xdg_paths).sync()
    assert list(foreign.iterdir()) == []


def test_reviewed_allowlist_contract_is_strict(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "e" * 40
    lock = ProviderLock(
        "https://github.com/vulhub/vulhub",
        commit,
        f"https://codeload.github.com/vulhub/vulhub/tar.gz/{commit}",
        "sha256:" + "a" * 64,
        "MIT",
    )
    monkeypatch.setattr(provider_module, "load_provider_lock", lambda: lock)
    provider = VulhubProvider(xdg_paths)

    def validate(value: dict[str, object]) -> None:
        monkeypatch.setattr(provider_module, "_load_resource", lambda name: value)
        provider._allowlist()

    valid = reviewed_allowlist(commit)
    validate(valid)

    def item(value: dict[str, object]) -> dict[str, Any]:
        return value["demo/CVE-2020-0001"]  # type: ignore[return-value]

    mutations: tuple[Callable[[dict[str, object]], None], ...] = (
        lambda value: value.update({"../escape": value.pop("demo/CVE-2020-0001")}),
        lambda value: item(value).update({"provider_commit": "f" * 40}),
        lambda value: item(value).update({"compose_sha256": "bad"}),
        lambda value: item(value).update({"images": []}),
        lambda value: item(value).update({"images": ["demo:latest"]}),
        lambda value: item(value).update({"commands": ["bad command"]}),
        lambda value: item(value)["review"].update({"unknown": True}),
        lambda value: item(value)["review"].update({"status": "pending"}),
        lambda value: item(value)["review"].update({"container_escape_exercise": True}),
        lambda value: item(value)["review"].update({"reviewed_at": "soon"}),
        lambda value: item(value)["review"].update({"reviewed_at": "2026-02-30"}),
        lambda value: item(value)["review"].update({"reviewer": ""}),
        lambda value: item(value)["review"].update({"provenance_evidence": []}),
        lambda value: item(value)["review"].update({"license_evidence": ["file:///tmp/license"]}),
        lambda value: item(value)["review"].update({"architectures": ["linux/unknown"]}),
        lambda value: item(value)["review"].update(
            {"architectures": ["linux/amd64", "linux/amd64"]}
        ),
        lambda value: item(value)["review"].update({"functionality_evidence": []}),
    )
    for mutation in mutations:
        changed = copy.deepcopy(valid)
        mutation(changed)
        with pytest.raises(IntegrityError, match="allowlist"):
            validate(changed)


def test_reviewed_compose_checksum_change_fails_closed(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    commit = "f" * 40
    content = archive(commit)
    VulhubProvider._extract(content, tmp_path / "extract", commit)
    extracted = tmp_path / "extract" / f"vulhub-{commit}"
    allowlist = reviewed_allowlist(commit)
    monkeypatch.setattr(VulhubProvider, "_allowlist", lambda self: allowlist)
    with pytest.raises(IntegrityError, match="checksum changed"):
        VulhubProvider(xdg_paths)._index(extracted)


def test_cached_index_rejects_unsafe_terminal_content() -> None:
    value = [
        {
            "path": "demo/CVE-2020-0001",
            "product": "Demo",
            "category": "RCE",
            "cves": ["CVE-2020-0001"],
            "status": "blocked",
            "reasons": ["unsafe\nterminal"],
        }
    ]
    with pytest.raises(IntegrityError, match="unsafe field"):
        VulhubProvider._parse_entries(json.dumps(value).encode())


def test_cached_index_rejects_duplicate_json_keys() -> None:
    with pytest.raises(IntegrityError, match="malformed"):
        VulhubProvider._parse_entries(b'[{"path":"a","path":"b"}]')


def test_cached_index_rejects_noncanonical_provider_path() -> None:
    value = [
        {
            "path": "demo//CVE-2020-0001",
            "product": "Demo",
            "category": "RCE",
            "cves": ["CVE-2020-0001"],
            "status": "blocked",
            "reasons": ["not reviewed"],
        }
    ]
    with pytest.raises(IntegrityError, match="unsafe field"):
        VulhubProvider._parse_entries(json.dumps(value).encode())

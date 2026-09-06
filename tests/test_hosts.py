from __future__ import annotations

from pathlib import Path

import pytest

from vulndockyard.errors import IntegrityError, PolicyError
from vulndockyard.hosts import BEGIN, END, HostsManager, parse_managed_hosts, transform_hosts


def test_add_remove_round_trip_preserves_unrelated_bytes() -> None:
    original = b"127.0.0.1 localhost\n# comment with spaces  \n::1 localhost\n"
    added = transform_hosts(original, ("juice-shop.test",))
    assert added.startswith(original)
    assert added.endswith((BEGIN + "127.0.0.1\tjuice-shop.test\n" + END).encode())
    assert parse_managed_hosts(added) == ("juice-shop.test",)
    assert transform_hosts(added, ()) == original


def test_add_remove_round_trip_preserves_missing_final_newline() -> None:
    original = b"127.0.0.1 localhost\n# unrelated final line"
    added = transform_hosts(original, ("juice-shop.test",))
    assert b"# VULNDOCKYARD INSERTED NEWLINE\n" in added
    assert parse_managed_hosts(added) == ("juice-shop.test",)
    assert transform_hosts(added, ()) == original


def test_transform_is_idempotent_and_sorted() -> None:
    original = b"127.0.0.1 localhost\n"
    once = transform_hosts(original, ("webgoat.test", "juice-shop.test"))
    twice = transform_hosts(once, ("juice-shop.test", "webgoat.test"))
    assert once == twice
    assert parse_managed_hosts(once) == ("juice-shop.test", "webgoat.test")


@pytest.mark.parametrize("hostname", ("UPPER.test", "escape.test.example", "-bad.test"))
def test_transform_rejects_unsafe_hostname(hostname: str) -> None:
    with pytest.raises(IntegrityError, match="lowercase"):
        transform_hosts(b"127.0.0.1 localhost\n", (hostname,))


@pytest.mark.parametrize(
    "content",
    [
        BEGIN.encode() + b"127.0.0.1 x.test\n",
        (BEGIN + END + BEGIN + END).encode(),
        (BEGIN + "0.0.0.0\tx.test\n" + END).encode(),
        b"hosts\x00file",
    ],
)
def test_malformed_managed_content_fails_closed(content: bytes) -> None:
    with pytest.raises(IntegrityError):
        transform_hosts(content, ("juice-shop.test",))


def test_manager_atomic_update_preserves_mode(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n# untouched\n"
    path.write_bytes(original)
    path.chmod(0o640)
    manager = HostsManager(path)
    preview = manager.preview("juice-shop.test", add=True)
    assert preview.changed
    manager.apply("juice-shop.test", add=True)
    assert path.stat().st_mode & 0o777 == 0o640
    manager.apply("juice-shop.test", add=True)
    manager.apply("juice-shop.test", add=False)
    assert path.read_bytes() == original


def test_manager_rejects_symlink_and_unsafe_mode(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    link = tmp_path / "hosts"
    link.symlink_to(target)
    with pytest.raises(PolicyError, match="symlinked"):
        HostsManager(link).preview("juice-shop.test", add=True)
    link.unlink()
    link.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    link.chmod(0o666)
    with pytest.raises(PolicyError, match="world-writable"):
        HostsManager(link).preview("juice-shop.test", add=True)


def test_manager_rejects_oversized_and_nul_content(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    path.write_bytes(b"x" * 2_000_001)
    path.chmod(0o600)
    with pytest.raises(PolicyError, match="2 MB"):
        HostsManager(path).preview("juice-shop.test", add=True)
    path.write_bytes(b"127.0.0.1 localhost\n\x00")
    with pytest.raises(IntegrityError, match="NUL"):
        HostsManager(path).preview("juice-shop.test", add=True)

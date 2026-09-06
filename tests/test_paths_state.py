from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulndockyard.errors import IntegrityError
from vulndockyard.paths import Paths, assert_owned_path, remove_owned_tree
from vulndockyard.state import ResourceRecord, RunState, StateStore


def test_xdg_discovery_and_permissions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    paths = Paths.discover()
    paths.ensure()
    for path in paths.owned_roots():
        assert path.name == "vulndockyard"
        assert path.stat().st_mode & 0o777 == 0o700


def test_guarded_deletion_rejects_root_escape_and_symlink(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    target = root / "lab"
    target.mkdir(parents=True)
    (target / "state").write_text("x", encoding="utf-8")
    assert assert_owned_path(target, root) == target
    with pytest.raises(IntegrityError, match="outside"):
        assert_owned_path(tmp_path / "other", root)
    with pytest.raises(IntegrityError, match="outside"):
        assert_owned_path(root, root)
    link = root / "link"
    link.symlink_to(tmp_path)
    with pytest.raises(IntegrityError, match="symlinked"):
        remove_owned_tree(link, root)
    remove_owned_tree(target, root)
    assert not target.exists()


def state() -> RunState:
    return RunState.create(
        lab_id="juice-shop",
        run_id="a" * 32,
        manifest_identity="b" * 64,
        host_port=80,
        trusted=True,
        requested_reference="example/app@sha256:" + "c" * 64,
        resolved_digest="sha256:" + "c" * 64,
        resources=(ResourceRecord("container", "app", "d" * 64),),
        created_at="2026-09-06T00:00:00Z",
    )


def test_state_round_trip_is_atomic_and_idempotent(xdg_paths: Paths) -> None:
    store = StateStore(xdg_paths)
    value = state()
    store.save(value)
    assert store.load("juice-shop") == value
    assert store.path("juice-shop").stat().st_mode & 0o777 == 0o600
    assert store.all() == (value,)
    store.delete("juice-shop")
    store.delete("juice-shop")
    assert store.load("juice-shop") is None


def test_state_fails_closed_on_unknown_data_and_symlink(xdg_paths: Paths, tmp_path: Path) -> None:
    store = StateStore(xdg_paths)
    store.save(state())
    path = store.path("juice-shop")
    value = json.loads(path.read_text(encoding="utf-8"))
    value["unknown"] = True
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(IntegrityError, match="unknown"):
        store.load("juice-shop")
    path.unlink()
    path.symlink_to(tmp_path / "missing")
    with pytest.raises(IntegrityError, match="symlink"):
        store.load("juice-shop")

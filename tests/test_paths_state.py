from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from vulndockyard.errors import IntegrityError, PreflightError
from vulndockyard.paths import Paths, assert_owned_path, remove_owned_tree
from vulndockyard.state import ResourceRecord, RunState, StateStore, UpdateJournal


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


def test_relative_xdg_path_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", "relative/state")
    with pytest.raises(IntegrityError, match="absolute"):
        Paths.discover()


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
        requested_reference="registry.example.test/app@sha256:" + "c" * 64,
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


def test_v2_state_and_update_journal_round_trip_atomically(xdg_paths: Paths) -> None:
    store = StateStore(xdg_paths)
    previous = RunState.create(
        lab_id="juice-shop",
        run_id="a" * 32,
        manifest_identity="b" * 64,
        host_port=80,
        trusted=True,
        requested_reference="registry.example.test/app@sha256:" + "c" * 64,
        resolved_digest="sha256:" + "c" * 64,
        resources=(ResourceRecord("container", "app", "d" * 64),),
        gateway_reference="registry.example.test/gateway@sha256:" + "3" * 64,
        upstream_port=3000,
        created_at="2026-09-06T00:00:00Z",
    )
    candidate = RunState.create(
        lab_id="juice-shop",
        run_id="e" * 32,
        manifest_identity="f" * 64,
        host_port=28080,
        trusted=True,
        requested_reference="registry.example.test/app@sha256:" + "1" * 64,
        resolved_digest="sha256:" + "1" * 64,
        resources=(),
        gateway_reference="registry.example.test/gateway@sha256:" + "2" * 64,
        upstream_port=3000,
        created_at="2026-09-06T00:00:00Z",
    )
    assert candidate.schema_version == 2
    journal = UpdateJournal(
        1,
        "juice-shop",
        "staged",
        previous,
        candidate,
        ("application", "gateway"),
        28080,
    )

    store.save_update(journal)
    assert store.load_update("juice-shop") == journal
    assert store.update_path("juice-shop").stat().st_mode & 0o777 == 0o600
    store.delete_update("juice-shop")
    assert store.load_update("juice-shop") is None


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
    with pytest.raises(IntegrityError, match="lab ID"):
        store.path("../escape")


def test_state_rejects_duplicate_keys_unsafe_mode_and_noncanonical_time(
    xdg_paths: Paths,
) -> None:
    store = StateStore(xdg_paths)
    store.save(state())
    path = store.path("juice-shop")
    content = path.read_text(encoding="utf-8")
    path.write_text(content.replace('"schema_version":1', '"schema_version":1,"schema_version":1'))
    with pytest.raises(IntegrityError, match="duplicate JSON object key"):
        store.load("juice-shop")
    store.save(state())
    path.chmod(0o640)
    with pytest.raises(IntegrityError, match="unsafe type"):
        store.load("juice-shop")
    raw = json.loads(json.dumps(state(), default=lambda item: item.__dict__))
    raw["created_at"] = "2026-09-06T02:00:00+02:00"
    with pytest.raises(IntegrityError, match="creation timestamp"):
        RunState.parse(raw)


def test_state_rejects_boolean_port_and_reference_digest_mismatch() -> None:
    raw = json.loads(json.dumps(state(), default=lambda item: item.__dict__))
    raw["host_port"] = True
    with pytest.raises(IntegrityError, match="host port"):
        RunState.parse(raw)

    raw = json.loads(json.dumps(state(), default=lambda item: item.__dict__))
    raw["resolved_digest"] = "sha256:" + "f" * 64
    with pytest.raises(IntegrityError, match="requested reference"):
        RunState.parse(raw)


def test_state_filename_is_bound_to_the_recorded_lab(xdg_paths: Paths) -> None:
    store = StateStore(xdg_paths)
    store.save(state())
    path = store.path("juice-shop")
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["lab_id"] = "webgoat"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(IntegrityError, match="filename"):
        store.load("juice-shop")


def test_state_rejects_untrusted_terminal_and_resource_fields() -> None:
    value = json.loads(json.dumps(state(), default=lambda item: item.__dict__))
    value["requested_reference"] = "image@sha256:" + "c" * 64 + "\nterminal"
    with pytest.raises(IntegrityError, match="requested reference"):
        RunState.parse(value)
    value = json.loads(json.dumps(state(), default=lambda item: item.__dict__))
    value["resources"][0]["kind"] = "host"
    with pytest.raises(IntegrityError, match="resource kind"):
        RunState.parse(value)


def test_lifecycle_lock_is_bounded_across_independent_stores(xdg_paths: Paths) -> None:
    first = StateStore(xdg_paths)
    second = StateStore(xdg_paths)
    failures: list[BaseException] = []

    def contend() -> None:
        try:
            with second.lifecycle_lock(timeout=0.05):
                pass
        except BaseException as exc:
            failures.append(exc)

    with first.lifecycle_lock(timeout=1):
        worker = threading.Thread(target=contend)
        worker.start()
        worker.join(timeout=1)
    assert not worker.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], PreflightError)


def test_lifecycle_lock_rejects_a_symlink(xdg_paths: Paths, tmp_path: Path) -> None:
    runs = xdg_paths.state / "runs"
    runs.mkdir(parents=True)
    (runs / ".lifecycle.lock").symlink_to(tmp_path / "attacker-lock")
    with (
        pytest.raises(IntegrityError, match="symlink"),
        StateStore(xdg_paths).lifecycle_lock(timeout=0.05),
    ):
        pass

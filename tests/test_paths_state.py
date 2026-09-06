from __future__ import annotations

import dataclasses
import json
import threading
from pathlib import Path
from typing import Any, cast

import pytest

from vulndockyard.errors import IntegrityError, PreflightError
from vulndockyard.models import EphemeralStorage, Service
from vulndockyard.paths import Paths, assert_owned_path, remove_owned_tree
from vulndockyard.state import (
    ResourceRecord,
    RunState,
    RuntimePolicySnapshot,
    StateStore,
    UpdateJournal,
)


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


def policy() -> RuntimePolicySnapshot:
    return RuntimePolicySnapshot(
        512,
        0.5,
        256,
        True,
        False,
        EphemeralStorage(65532, 65532, (), ()),
        "juice-shop.test",
        120,
        (Service("web", "application", 3000, "http", "/", "OWASP Juice Shop"),),
    )


def serialized_state() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(json.dumps(state().serializable())))


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


def test_v3_state_and_update_journal_round_trip_atomically(xdg_paths: Paths) -> None:
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
        runtime_policy=policy(),
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
        runtime_policy=policy(),
        created_at="2026-09-06T00:00:00Z",
    )
    assert candidate.schema_version == 3
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


def test_runtime_policy_snapshot_and_update_journal_fail_closed() -> None:
    raw_policy = {
        "memory_mb": 512,
        "cpus": 0.5,
        "pids": 256,
        "read_only_root": True,
        "outbound_required": False,
        "ephemeral_storage": {"uid": 65532, "gid": 65532, "seeded": [], "empty": []},
        "friendly_hostname": "juice-shop.test",
        "health_timeout_seconds": 120,
        "services": [
            {
                "name": "web",
                "image_role": "application",
                "internal_port": 3000,
                "protocol": "http",
                "health_path": "/",
                "identity_marker": "OWASP Juice Shop",
            }
        ],
    }
    for key, invalid in (
        ("memory_mb", True),
        ("read_only_root", False),
        ("outbound_required", "no"),
        ("friendly_hostname", "localhost"),
        ("health_timeout_seconds", True),
    ):
        invalid_policy = dict(raw_policy)
        invalid_policy[key] = invalid
        with pytest.raises(IntegrityError, match="runtime policy snapshot"):
            RuntimePolicySnapshot.parse(invalid_policy)
    unknown = dict(raw_policy)
    unknown["unknown"] = True
    with pytest.raises(IntegrityError, match="missing or unknown"):
        RuntimePolicySnapshot.parse(unknown)

    previous = RunState.create(
        lab_id="juice-shop",
        run_id="a" * 32,
        manifest_identity="b" * 64,
        host_port=80,
        trusted=True,
        requested_reference="registry.example.test/app@sha256:" + "c" * 64,
        resolved_digest="sha256:" + "c" * 64,
        resources=(),
        gateway_reference="registry.example.test/gateway@sha256:" + "3" * 64,
        upstream_port=3000,
        created_at="2026-09-06T00:00:00Z",
    )
    candidate = dataclasses.replace(
        previous,
        run_id="d" * 32,
        manifest_identity="e" * 64,
        host_port=28080,
    )
    legacy = UpdateJournal(
        1,
        "juice-shop",
        "staged",
        previous,
        candidate,
        ("application", "gateway"),
        28080,
    )
    persisted = json.loads(json.dumps(legacy.serializable()))
    with pytest.raises(IntegrityError, match="trusted rollback snapshot"):
        UpdateJournal.parse(persisted)

    mismatched_gateway = dataclasses.replace(
        previous,
        schema_version=3,
        upstream_port=3001,
        runtime_policy=policy(),
    )
    with pytest.raises(IntegrityError, match="health services differ"):
        RunState.parse(json.loads(json.dumps(mismatched_gateway.serializable())))


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
    raw = serialized_state()
    raw["created_at"] = "2026-09-06T02:00:00+02:00"
    with pytest.raises(IntegrityError, match="creation timestamp"):
        RunState.parse(raw)


def test_state_rejects_boolean_port_and_reference_digest_mismatch() -> None:
    raw = serialized_state()
    raw["host_port"] = True
    with pytest.raises(IntegrityError, match="host port"):
        RunState.parse(raw)

    raw = serialized_state()
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
    value = serialized_state()
    value["requested_reference"] = "image@sha256:" + "c" * 64 + "\nterminal"
    with pytest.raises(IntegrityError, match="requested reference"):
        RunState.parse(value)
    value = serialized_state()
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

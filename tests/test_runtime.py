from __future__ import annotations

import dataclasses
import io
import json
import urllib.request
from types import TracebackType
from typing import Any, Self, cast

import pytest

import vulndockyard.cli as cli
from vulndockyard.catalogue import Catalogue, ReviewedLab
from vulndockyard.docker import LAB, MANIFEST, OWNER, Ownership, Timeouts, expected_resource_role
from vulndockyard.errors import IntegrityError, PolicyError, PreflightError
from vulndockyard.paths import Paths
from vulndockyard.process import Result
from vulndockyard.runtime import Runtime, _NoRedirect
from vulndockyard.state import ResourceRecord, RunState, UpdateJournal


class FakeDocker:
    def __init__(self) -> None:
        self.timeouts = Timeouts(health=0.1)
        self.objects: dict[str, dict[str, Any]] = {}
        self.pulls: list[str] = []
        self.removed: list[str] = []
        self.image_removals: list[str] = []
        self.connections: list[tuple[str, str]] = []
        self.events: list[tuple[str, object]] = []
        self.ports: dict[int, str] = {}
        self.create_count = 0
        self.fail_gateway = False

    def _id(self) -> str:
        self.create_count += 1
        return f"{self.create_count:064x}"

    @staticmethod
    def _label_map(value: Ownership, role: str) -> dict[str, str]:
        raw = value.labels(role)
        return {
            raw[index + 1].split("=", 1)[0]: raw[index + 1].split("=", 1)[1]
            for index in range(0, len(raw), 2)
        }

    @staticmethod
    def _labels(kind: str, inspection: dict[str, Any]) -> dict[str, str]:
        value = inspection["Config"]["Labels"] if kind == "container" else inspection["Labels"]
        return cast(dict[str, str], value)

    def preflight(self, *, require_compose: bool = False) -> dict[str, object]:
        return {
            "engine": "test",
            "compose_v2": not require_compose,
            "platform": "linux/amd64",
        }

    def pull(self, reference: str) -> None:
        self.pulls.append(reference)

    def create_network(
        self, name: str, ownership: Ownership, *, internal: bool = True
    ) -> ResourceRecord:
        object_id = self._id()
        self.objects[object_id] = {
            "Id": object_id,
            "Name": name,
            "Labels": self._label_map(ownership, "network"),
            "Internal": internal,
        }
        return ResourceRecord("network", name, object_id)

    def create_application(self, **values: Any) -> ResourceRecord:
        object_id = self._id()
        owner: Ownership = values["ownership"]
        self.objects[object_id] = {
            "Id": object_id,
            "Name": values["name"],
            "Config": {
                "Labels": self._label_map(owner, "application"),
                "Image": values["image"],
            },
            "HostConfig": {"PortBindings": {}},
            "State": {"Running": False},
        }
        return ResourceRecord("container", values["name"], object_id)

    def create_gateway(self, **values: Any) -> ResourceRecord:
        if self.fail_gateway:
            raise PreflightError("synthetic gateway failure")
        port = values["host_port"]
        if port in self.ports:
            raise PreflightError(f"synthetic port reservation conflict: {port}")
        object_id = self._id()
        owner: Ownership = values["ownership"]
        self.objects[object_id] = {
            "Id": object_id,
            "Name": values["name"],
            "Config": {
                "Labels": self._label_map(owner, "gateway"),
                "Image": values["image"],
            },
            "HostConfig": {
                "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]}
            },
            "State": {"Running": False},
        }
        self.ports[port] = object_id
        self.events.append(("create-gateway", port))
        return ResourceRecord("container", values["name"], object_id)

    def connect_network(self, network: ResourceRecord, container: ResourceRecord) -> None:
        assert network.object_id in self.objects and container.object_id in self.objects
        self.connections.append((network.object_id, container.object_id))

    def inspect(self, kind: str, object_id: str) -> dict[str, Any]:
        return self.objects[object_id]

    def exists(self, kind: str, object_id: str) -> bool:
        return object_id in self.objects

    def validate_owned(self, record: ResourceRecord, ownership: Ownership) -> dict[str, Any]:
        inspection = self.objects[record.object_id]
        labels = self._labels(record.kind, inspection)
        expected = self._label_map(ownership, expected_resource_role(record, ownership))
        if inspection["Name"].removeprefix("/") != record.name:
            raise PolicyError("resource name mismatch")
        if any(labels.get(key) != value for key, value in expected.items()):
            raise PolicyError("ownership labels mismatch")
        return inspection

    def start(self, record: ResourceRecord) -> None:
        self.objects[record.object_id]["State"]["Running"] = True
        self.events.append(("start", record.name))

    def stop(self, record: ResourceRecord) -> None:
        self.objects[record.object_id]["State"]["Running"] = False
        self.events.append(("stop", record.name))

    def remove(self, record: ResourceRecord) -> None:
        self.removed.append(record.object_id)
        inspection = self.objects[record.object_id]
        if record.kind == "container":
            binding = inspection.get("HostConfig", {}).get("PortBindings", {}).get("8080/tcp")
            if binding:
                port = int(binding[0]["HostPort"])
                self.ports.pop(port, None)
                self.events.append(("remove-gateway", port))
        del self.objects[record.object_id]

    def remove_image(self, reference: str) -> None:
        self.image_removals.append(reference)

    def logs(self, record: ResourceRecord, *, follow: bool, tail: int = 100) -> Result:
        return Result(("docker", "logs"), 0, "application log\n", "")

    def managed_resources(self, *, lab_id: str | None = None) -> dict[str, tuple[str, ...]]:
        result: dict[str, list[str]] = {"container": [], "network": [], "volume": []}
        for object_id, inspection in self.objects.items():
            kind = "container" if "Config" in inspection else "network"
            labels = self._labels(kind, inspection)
            if labels.get(OWNER) == "true" and (lab_id is None or labels.get(LAB) == lab_id):
                result[kind].append(object_id)
        return {kind: tuple(object_ids) for kind, object_ids in result.items()}


class ReadyRuntime(Runtime):
    def __init__(self, *, paths: Paths, docker: FakeDocker) -> None:
        super().__init__(
            catalogue=Catalogue(),
            paths=paths,
            docker=docker,  # type: ignore[arg-type]
            temporary_port_selector=lambda excluded: 28080,
        )
        self.health_calls = 0
        self.fail_health = False
        self.fail_health_call: int | None = None

    def _health(self, lab: ReviewedLab, port: int) -> None:
        self.health_calls += 1
        self.docker.events.append(("health", port))  # type: ignore[attr-defined]
        if self.fail_health or self.health_calls == self.fail_health_call:
            raise PreflightError("synthetic candidate identity failure")


def runtime(paths: Paths) -> tuple[ReadyRuntime, FakeDocker, ReviewedLab]:
    docker = FakeDocker()
    value = ReadyRuntime(paths=paths, docker=docker)
    return value, docker, Catalogue().get("juice-shop")


def preserve_as_previous(value: ReadyRuntime, docker: FakeDocker, lab: ReviewedLab) -> RunState:
    state = value.store.load(lab.manifest.id)
    assert state is not None
    previous = dataclasses.replace(state, manifest_identity="e" * 64)
    for record in previous.resources:
        labels = docker._labels(record.kind, docker.objects[record.object_id])
        labels[MANIFEST] = previous.manifest_identity
    value.store.save(previous)
    return previous


def test_reference_lifecycle_is_idempotent_and_distinct(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    started = value.up(lab, host_port=18080)
    assert started.state == "running"
    assert started.lock_match
    assert started.url == "http://juice-shop.test:18080"
    assert len(started.resources) == 4
    assert len(docker.pulls) == 2
    state = value.store.load(lab.manifest.id)
    assert state is not None
    internal = next(record for record in state.resources if record.name.endswith("-net"))
    ingress = next(record for record in state.resources if record.name.endswith("-ingress"))
    assert docker.objects[internal.object_id]["Internal"] is True
    assert docker.objects[ingress.object_id]["Internal"] is False
    first_run = started.run_id
    first_count = docker.create_count

    repeated = value.up(lab, host_port=18080)
    assert repeated.run_id == first_run
    assert docker.create_count == first_count
    assert len(docker.pulls) == 2

    assert value.stop(lab).state == "stopped"
    assert value.stop(lab).state == "stopped"
    assert value.restart(lab).state == "running"
    rebuilt = value.rebuild(lab)
    assert rebuilt.run_id != first_run
    assert rebuilt.requested_reference == started.requested_reference
    reset = value.reset(lab)
    assert reset.run_id != rebuilt.run_id
    assert value.logs(lab, follow=False) == "application log\n"
    assert value.remove(lab).state == "absent"
    assert value.remove(lab).state == "absent"
    assert docker.objects == {}


def test_interrupted_startup_cleans_only_created_resources(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    docker.fail_gateway = True
    with pytest.raises(PreflightError, match="synthetic"):
        value.up(lab, host_port=18080)
    assert docker.objects == {}
    assert value.store.load(lab.manifest.id) is None
    assert len(docker.removed) == 3


def test_reviewed_update_current_and_no_runtime_are_non_mutating(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    absent = value.activate_reviewed_update(lab)
    assert absent.outcome == "no-runtime"
    assert docker.pulls == []

    started = value.up(lab, host_port=18080)
    created = docker.create_count
    current = value.activate_reviewed_update(lab)
    assert current.outcome == "already-current"
    assert current.active_run_id == started.run_id
    assert docker.create_count == created


def test_cli_activates_only_installed_reviewed_candidate_after_readiness(
    xdg_paths: Paths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    previous_ids = {record.object_id for record in previous.resources}
    monkeypatch.setattr(cli, "Runtime", lambda catalogue=None: value)
    monkeypatch.setattr(
        cli,
        "check_latest",
        lambda selected: (_ for _ in ()).throw(AssertionError("discovery must not activate")),
    )

    assert cli.main(["--json", "update", "juice-shop"]) == 0
    result = json.loads(capsys.readouterr().out)["data"]["results"][0]
    assert result["outcome"] == "activated"
    assert result["previous_run_id"] == previous.run_id
    assert result["candidate_manifest_identity"] == lab.manifest_identity
    active = value.store.load(lab.manifest.id)
    assert active is not None and active.manifest_identity == lab.manifest_identity
    assert active.run_id != previous.run_id
    assert previous_ids.isdisjoint(docker.objects)
    assert len(docker.objects) == 4


def test_update_smokes_on_temporary_port_before_exact_gateway_cutover(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    preserve_as_previous(value, docker, lab)
    docker.events.clear()

    value.activate_reviewed_update(lab)

    assert docker.events.index(("create-gateway", 28080)) < docker.events.index(("health", 28080))
    assert docker.events.index(("health", 28080)) < docker.events.index(("remove-gateway", 28080))
    first_old_removal = docker.events.index(("remove-gateway", 18080))
    final_creation = docker.events.index(("create-gateway", 18080))
    assert docker.events.index(("remove-gateway", 28080)) < first_old_removal
    assert first_old_removal < final_creation
    assert final_creation < docker.events.index(("health", 18080))
    assert docker.ports == {18080: next(iter(docker.ports.values()))}
    assert value.store.load_update(lab.manifest.id) is None


def test_final_port_failure_recreates_prior_gateway_and_running_state(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    old_gateway = next(record for record in previous.resources if record.name.endswith("-gateway"))
    unchanged_ids = {record.object_id for record in previous.resources if record != old_gateway}
    value.fail_health_call = value.health_calls + 2
    docker.events.clear()

    with pytest.raises(PreflightError, match="candidate identity failure"):
        value.activate_reviewed_update(lab)

    restored = value.store.load(lab.manifest.id)
    assert restored is not None
    assert restored.run_id == previous.run_id
    assert restored.manifest_identity == previous.manifest_identity
    restored_gateway = next(
        record for record in restored.resources if record.name.endswith("-gateway")
    )
    assert restored_gateway.object_id != old_gateway.object_id
    assert unchanged_ids.issubset(docker.objects)
    assert docker.events.index(("create-gateway", 28080)) < docker.events.index(
        ("remove-gateway", 18080)
    )
    final_candidate = docker.events.index(("create-gateway", 18080))
    final_failure = docker.events.index(("health", 18080))
    restored_creation = docker.events.index(("create-gateway", 18080), final_candidate + 1)
    assert final_candidate < final_failure < restored_creation
    assert all(
        docker.objects[record.object_id]["State"]["Running"]
        for record in restored.resources
        if record.kind == "container"
    )
    assert docker.ports == {18080: restored_gateway.object_id}
    assert value.store.load_update(lab.manifest.id) is None


def test_next_lifecycle_command_rolls_back_an_interrupted_cutover(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    candidate = value._create_run(
        lab,
        host_port=28080,
        selected_reference=lab.manifest.images[0].reference,
        trusted=True,
        persist=False,
        coexisting=(previous,),
    )
    candidate_inspections = value._validate_state(candidate)
    temporary_gateway = next(
        record
        for record, inspection in zip(candidate.resources, candidate_inspections, strict=True)
        if record.kind == "container"
        and docker._labels(record.kind, inspection).get("org.vulndockyard.role") == "gateway"
    )
    docker.remove(temporary_gateway)
    candidate = dataclasses.replace(
        candidate,
        host_port=previous.host_port,
        resources=tuple(record for record in candidate.resources if record != temporary_gateway),
    )
    old_gateway = next(record for record in previous.resources if record.name.endswith("-gateway"))
    docker.remove(old_gateway)
    ingress = next(record for record in candidate.resources if record.name.endswith("-ingress"))
    internal = next(record for record in candidate.resources if record.name.endswith("-net"))
    unjournaled_gateway = docker.create_gateway(
        name=temporary_gateway.name,
        image=lab.manifest.images[1].reference,
        network=ingress.name,
        upstream_port=lab.manifest.services[0].internal_port,
        host_port=previous.host_port,
        ownership=Ownership.from_state(candidate),
    )
    docker.connect_network(internal, unjournaled_gateway)
    value.store.save_update(
        UpdateJournal(
            1,
            lab.manifest.id,
            "cutover",
            previous,
            candidate,
            ("application", "gateway"),
            28080,
        )
    )

    status = value.status(lab)

    assert status.run_id == previous.run_id
    assert status.state == "running"
    assert value.store.load_update(lab.manifest.id) is None
    assert unjournaled_gateway.object_id not in docker.objects
    assert docker.ports.keys() == {18080}


def test_ready_journal_completes_cleanup_after_interruption(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    original_cleanup = value._cleanup

    def interrupt_old_cleanup(state: RunState, *, coexisting: tuple[RunState, ...] = ()) -> None:
        if state.run_id == previous.run_id:
            raise PreflightError("synthetic cleanup interruption")
        original_cleanup(state, coexisting=coexisting)

    monkeypatch.setattr(value, "_cleanup", interrupt_old_cleanup)
    with pytest.raises(PreflightError, match="cleanup interruption"):
        value.activate_reviewed_update(lab)
    journal = value.store.load_update(lab.manifest.id)
    assert journal is not None and journal.phase == "ready"
    active = value.store.load(lab.manifest.id)
    assert active is not None and active.run_id == journal.candidate.run_id

    monkeypatch.setattr(value, "_cleanup", original_cleanup)
    recovered = value.status(lab)

    assert recovered.run_id == active.run_id
    assert recovered.lock_match
    assert value.store.load_update(lab.manifest.id) is None
    assert len(docker.objects) == 4


def test_cli_failed_candidate_restores_previous_runtime_and_discards_candidate(
    xdg_paths: Paths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    previous_ids = {record.object_id for record in previous.resources}
    value.fail_health = True
    monkeypatch.setattr(cli, "Runtime", lambda catalogue=None: value)
    monkeypatch.setattr(
        cli,
        "check_latest",
        lambda selected: (_ for _ in ()).throw(AssertionError("discovery must not activate")),
    )

    assert cli.main(["update", "juice-shop"]) == 5
    assert "candidate identity failure" in capsys.readouterr().err
    assert value.store.load(lab.manifest.id) == previous
    assert set(docker.objects) == previous_ids
    assert all(
        docker.objects[record.object_id]["State"]["Running"]
        for record in previous.resources
        if record.kind == "container"
    )


def test_update_preserves_a_stopped_runtime_as_stopped(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    value.stop(lab)
    previous = preserve_as_previous(value, docker, lab)

    result = value.activate_reviewed_update(lab)

    assert result.outcome == "activated"
    assert result.status.state == "stopped"
    active = value.store.load(lab.manifest.id)
    assert active is not None and active.run_id != previous.run_id
    assert all(
        not docker.objects[record.object_id]["State"]["Running"]
        for record in active.resources
        if record.kind == "container"
    )


def test_failed_update_restores_exact_prior_running_roles(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    gateway = next(record for record in state.resources if record.name.endswith("-gateway"))
    docker.stop(gateway)
    previous = preserve_as_previous(value, docker, lab)
    value.fail_health = True

    with pytest.raises(PreflightError, match="candidate identity failure"):
        value.activate_reviewed_update(lab)

    assert value.store.load(lab.manifest.id) == previous
    running_by_role = {
        docker._labels(record.kind, docker.objects[record.object_id]).get(
            "org.vulndockyard.role"
        ): docker.objects[record.object_id]["State"]["Running"]
        for record in previous.resources
        if record.kind == "container"
    }
    assert running_by_role == {"application": True, "gateway": False}


def test_update_rejects_a_candidate_not_bound_to_its_reviewed_lock(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    pulls_before = tuple(docker.pulls)
    arbitrary = dataclasses.replace(lab.manifest.images[0], name="attacker.invalid/image")
    bad_manifest = dataclasses.replace(lab.manifest, images=(arbitrary, *lab.manifest.images[1:]))
    candidate = dataclasses.replace(lab, manifest=bad_manifest)
    with pytest.raises(IntegrityError, match="do not match its immutable lock"):
        value.activate_reviewed_update(candidate)
    assert tuple(docker.pulls) == pulls_before
    assert value.store.load(lab.manifest.id) == previous


def test_next_start_recovers_exact_owned_partial_checkpoint(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    ownership = Ownership(
        lab.manifest.id,
        lab.manifest_identity,
        "a" * 32,
        "2026-09-06T00:00:00Z",
        True,
    )
    partial = docker.create_network("vdy-juice-shop-aaaaaaaaaaaa-net", ownership)
    value.store.save(
        RunState.create(
            lab_id=lab.manifest.id,
            run_id=ownership.run_id,
            manifest_identity=lab.manifest_identity,
            host_port=18080,
            trusted=True,
            requested_reference=lab.manifest.images[0].reference,
            resolved_digest=lab.manifest.images[0].digest,
            resources=(partial,),
            created_at=ownership.created_at,
        )
    )
    recovered = value.up(lab, host_port=18080)
    assert recovered.state == "running"
    assert recovered.run_id != ownership.run_id
    assert partial.object_id in docker.removed


def test_existing_state_requires_exact_ownership_and_manifest_identity(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    application = next(record for record in state.resources if record.name.endswith("-app"))
    docker.objects[application.object_id]["Config"]["Labels"]["org.vulndockyard.lab-id"] = "other"
    with pytest.raises(PolicyError, match="ownership"):
        value.up(lab, host_port=18080)
    with pytest.raises(PolicyError, match="ownership"):
        value.remove(lab)


def test_cleanup_prevalidates_every_resource_before_removing_anything(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    gateway = next(record for record in state.resources if record.name.endswith("-gateway"))
    docker.objects[gateway.object_id]["Name"] = "unrelated"
    with pytest.raises(PolicyError, match="name mismatch"):
        value.remove(lab)
    assert docker.removed == []
    assert len(docker.objects) == 4
    assert value.store.load(lab.manifest.id) == state


def test_runtime_inventory_never_infers_ownership_from_an_id_prefix(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    container = next(record for record in state.resources if record.kind == "container")
    monkeypatch.setattr(
        docker,
        "managed_resources",
        lambda lab_id=None: {
            "container": (container.object_id[:12],),
            "network": (),
            "volume": (),
        },
    )

    with pytest.raises(PolicyError, match="without usable runtime state"):
        value.stop(lab)


def test_missing_state_orphans_are_never_inferred_or_removed(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    ownership = Ownership(
        lab.manifest.id,
        lab.manifest_identity,
        "a" * 32,
        "2026-09-06T00:00:00Z",
        True,
    )
    orphan = docker.create_network("vdy-juice-shop-aaaaaaaaaaaa-net", ownership)
    with pytest.raises(PolicyError, match="without usable runtime state"):
        value.remove(lab)
    with pytest.raises(PolicyError, match="unrecorded managed Docker resources"):
        value.up(lab, host_port=18080)
    assert orphan.object_id in docker.objects
    assert docker.removed == []


def test_single_lab_start_blocks_unrecorded_resources_from_any_lab(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    ownership = Ownership(
        "other",
        "b" * 64,
        "a" * 32,
        "2026-09-06T00:00:00Z",
        True,
    )
    orphan = docker.create_network("vdy-other-aaaaaaaaaaaa-net", ownership)
    with pytest.raises(PolicyError, match="unrecorded managed Docker resources"):
        value.up(lab, host_port=18080)
    assert orphan.object_id in docker.objects
    assert docker.pulls == []


def test_unsafe_override_never_inherits_trust(
    xdg_paths: Paths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    value, _, lab = runtime(xdg_paths)
    image = "dev.example/app@sha256:" + "f" * 64
    with pytest.raises(PolicyError, match="requires --unsafe-development"):
        value.up(lab, unsafe_image=image)
    result = value.up(lab, host_port=18080, unsafe_image=image, unsafe_development=True)
    assert not result.trusted_run
    assert not result.lock_match
    assert result.trust_level == "untrusted-development"
    assert result.requested_reference == image
    monkeypatch.setattr(cli, "Runtime", lambda catalogue=None: value)
    assert cli.main(["--json", "status", "juice-shop"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["data"][0]["trust_level"] == "untrusted-development"
    assert document["data"][0]["lock_match"] is False
    assert cli.main(["status", "juice-shop"]) == 0
    human = capsys.readouterr().out
    assert "UNTRUSTED development run" in human
    assert "Trust: untrusted-development" in human
    value.stop(lab)
    with pytest.raises(PolicyError, match="preserved runtime is an untrusted"):
        value.up(lab, host_port=18080)
    resumed = value.up(lab, host_port=18080, unsafe_development=True)
    assert resumed.run_id == result.run_id
    assert not resumed.trusted_run
    with pytest.raises(PolicyError, match="does not match the preserved untrusted runtime"):
        value.up(
            lab,
            host_port=18080,
            unsafe_image="dev.example/other@sha256:" + "e" * 64,
            unsafe_development=True,
        )
    with pytest.raises(PolicyError, match="immutable"):
        value.up(
            lab,
            unsafe_image="--host/app@sha256:" + "f" * 64,
            unsafe_development=True,
        )


@pytest.mark.parametrize("role", ["application", "gateway"])
def test_lock_match_checks_each_inspected_container_image(xdg_paths: Paths, role: str) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    record = next(
        record
        for record in state.resources
        if record.kind == "container"
        and docker._labels(record.kind, docker.objects[record.object_id]).get(
            "org.vulndockyard.role"
        )
        == role
    )
    docker.objects[record.object_id]["Config"]["Image"] = (
        "attacker.invalid/image@sha256:" + "9" * 64
    )

    assert value.status(lab).lock_match is False


def test_restart_and_rebuild_refuse_to_replace_preserved_old_lock(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    previous = preserve_as_previous(value, docker, lab)
    previous_ids = set(docker.objects)
    removed_before = tuple(docker.removed)
    created_before = docker.create_count

    with pytest.raises(PolicyError, match="use update"):
        value.restart(lab)
    with pytest.raises(PolicyError, match="use update"):
        value.rebuild(lab)

    assert value.store.load(lab.manifest.id) == previous
    assert set(docker.objects) == previous_ids
    assert tuple(docker.removed) == removed_before
    assert docker.create_count == created_before
    assert all(
        docker.objects[record.object_id]["State"]["Running"]
        for record in previous.resources
        if record.kind == "container"
    )


def test_rebuild_refuses_an_untrusted_reference_before_cleanup(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    image = "dev.example/app@sha256:" + "f" * 64
    value.up(lab, host_port=18080, unsafe_image=image, unsafe_development=True)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    ids_before = set(docker.objects)

    with pytest.raises(PolicyError, match="reference differs"):
        value.rebuild(lab)

    assert value.store.load(lab.manifest.id) == state
    assert set(docker.objects) == ids_before
    assert docker.removed == []


def test_pull_fails_before_docker_for_an_unsupported_host_architecture(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    images = tuple(
        dataclasses.replace(image, architectures=("linux/arm64",)) for image in lab.manifest.images
    )
    manifest = dataclasses.replace(lab.manifest, images=images)
    unsupported = dataclasses.replace(lab, manifest=manifest)
    with pytest.raises(PreflightError, match="does not support linux/amd64"):
        value.pull(unsupported)
    assert docker.pulls == []


def test_single_lab_default_and_egress_acknowledgement(xdg_paths: Paths) -> None:
    value, _, juice = runtime(xdg_paths)
    value.up(juice, host_port=18080)
    with pytest.raises(PolicyError, match="is quarantined"):
        value.up(Catalogue().get("crapi"), host_port=18081)


def test_purge_images_uses_only_locked_digest_references(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    value.purge(lab, images=True)
    assert set(docker.image_removals) == {image.reference for image in lab.manifest.images}


class HealthResponse(io.BytesIO):
    def __init__(self, value: bytes, url: str) -> None:
        super().__init__(value)
        self.url = url

    def geturl(self) -> str:
        return self.url

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def test_real_health_checks_application_identity_and_functionality(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, juice_shop: ReviewedLab
) -> None:
    docker = FakeDocker()
    runtime_value = Runtime(paths=xdg_paths, docker=docker)  # type: ignore[arg-type]
    bodies = iter((b"<title>OWASP Juice Shop</title>", b'{"passwordHashLeakChallenge":true}'))
    monkeypatch.setattr(
        "vulndockyard.runtime._open_local_health",
        lambda request, timeout: HealthResponse(next(bodies), request.full_url),
    )
    runtime_value._health(juice_shop, 18080)


def test_health_identity_mismatch_times_out_truthfully(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, juice_shop: ReviewedLab
) -> None:
    docker = FakeDocker()
    runtime_value = Runtime(paths=xdg_paths, docker=docker, sleeper=lambda value: None)  # type: ignore[arg-type]
    moments = iter((0.0, 0.0, 1.0, 1.0))
    monkeypatch.setattr("vulndockyard.runtime.time.monotonic", lambda: next(moments, 1.0))
    monkeypatch.setattr(
        "vulndockyard.runtime._open_local_health",
        lambda request, timeout: HealthResponse(b"wrong application", request.full_url),
    )
    with pytest.raises(PreflightError, match="identity verification timed out"):
        runtime_value._health(juice_shop, 18080)


def test_health_rejects_an_effective_url_change(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, juice_shop: ReviewedLab
) -> None:
    runtime_value = Runtime(paths=xdg_paths, docker=FakeDocker())  # type: ignore[arg-type]
    monkeypatch.setattr(
        "vulndockyard.runtime._open_local_health",
        lambda request, timeout: HealthResponse(b"OWASP Juice Shop", "http://attacker.invalid/"),
    )
    with pytest.raises(IntegrityError, match="escaped its fixed loopback URL"):
        runtime_value._health(juice_shop, 18080)


def test_health_uses_the_lower_reviewed_manifest_timeout(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, juice_shop: ReviewedLab
) -> None:
    docker = FakeDocker()
    docker.timeouts = Timeouts(health=120)
    raw = dict(juice_shop.manifest.raw)
    raw["health_check"] = {**raw["health_check"], "timeout_seconds": 2}
    reviewed = dataclasses.replace(
        juice_shop, manifest=dataclasses.replace(juice_shop.manifest, raw=raw)
    )
    timeouts: list[float] = []

    def ready(request: urllib.request.Request, *, timeout: float) -> HealthResponse:
        timeouts.append(timeout)
        return HealthResponse(b"OWASP Juice Shop passwordHashLeakChallenge", request.full_url)

    monkeypatch.setattr("vulndockyard.runtime._open_local_health", ready)
    Runtime(paths=xdg_paths, docker=docker)._health(reviewed, 18080)  # type: ignore[arg-type]
    assert timeouts and set(timeouts) == {2.0}


def test_health_redirect_handler_never_follows_redirects() -> None:
    request = urllib.request.Request("http://127.0.0.1:8080/")
    _NoRedirect().redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "http://attacker.invalid/",
    )


def test_runtime_pull_verify_open_and_residual_audit(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    value, _docker, lab = runtime(xdg_paths)
    assert value.pull(lab) == tuple(image.reference for image in lab.manifest.images)
    value.up(lab, host_port=18080)
    assert value.verify(lab).lock_match
    monkeypatch.setattr("vulndockyard.runtime.webbrowser.open", lambda url: True)
    assert value.open(lab) == "http://juice-shop.test:18080"
    audit = value.residual_audit()
    assert len(audit["container"]) == 2
    assert len(audit["network"]) == 2
    assert audit["volume"] == ()
    value.stop(lab)
    with pytest.raises(PolicyError, match="not running"):
        value.verify(lab)
    with pytest.raises(PolicyError, match="not running"):
        value.open(lab)


def test_runtime_rejects_invalid_port_egress_and_multiple_state(xdg_paths: Paths) -> None:
    value, _, lab = runtime(xdg_paths)
    for invalid_port in (0, True):
        with pytest.raises(PolicyError, match="between 1 and 65535"):
            value.up(lab, host_port=invalid_port)
    egress_manifest = dataclasses.replace(lab.manifest, outbound_required=True)
    egress_lab = dataclasses.replace(lab, manifest=egress_manifest)
    with pytest.raises(PolicyError, match="acknowledge-egress"):
        value.up(egress_lab, host_port=18080)
    value.store.save(
        RunState.create(
            lab_id="other",
            run_id="a" * 32,
            manifest_identity="b" * 64,
            host_port=18081,
            trusted=True,
            requested_reference="registry.example.test/app@sha256:" + "c" * 64,
            resolved_digest="sha256:" + "c" * 64,
            resources=(),
        )
    )
    with pytest.raises(PolicyError, match="another lab"):
        value.up(lab, host_port=18080)


def test_status_reports_partially_running_layout_as_degraded(xdg_paths: Paths) -> None:
    value, docker, lab = runtime(xdg_paths)
    value.up(lab, host_port=18080)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    application = next(record for record in state.resources if record.name.endswith("-app"))
    docker.objects[application.object_id]["State"]["Running"] = False

    assert value.status(lab).state == "degraded"


def test_acknowledged_required_egress_attaches_only_app_to_reviewed_ingress(
    xdg_paths: Paths,
) -> None:
    value, docker, lab = runtime(xdg_paths)
    egress_manifest = dataclasses.replace(lab.manifest, outbound_required=True)
    egress_lab = dataclasses.replace(lab, manifest=egress_manifest)

    with pytest.raises(PolicyError, match="acknowledge-egress"):
        value.up(egress_lab, host_port=18080)
    assert docker.connections == []

    value.up(egress_lab, host_port=18080, acknowledge_egress=True)
    state = value.store.load(lab.manifest.id)
    assert state is not None
    ingress = next(record for record in state.resources if record.name.endswith("-ingress"))
    application = next(record for record in state.resources if record.name.endswith("-app"))
    gateway = next(record for record in state.resources if record.name.endswith("-gateway"))
    internal = next(record for record in state.resources if record.name.endswith("-net"))
    assert set(docker.connections) == {
        (internal.object_id, gateway.object_id),
        (ingress.object_id, application.object_id),
    }
    assert docker.objects[ingress.object_id]["Internal"] is False

"""Generic safe lab lifecycle."""

from __future__ import annotations

import contextlib
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from typing import Any

from .catalogue import Catalogue, ReviewedLab, identity, template_identity
from .docker import MINIMUM_ENGINE_TEXT, ROLE, SEED_READY_MARKER, Docker, Ownership
from .errors import IntegrityError, PolicyError, PreflightError, VulnDockyardError
from .models import DIGEST, OCI_NAME, AdapterStatus, EphemeralMount, Image
from .paths import Paths
from .state import ResourceRecord, RunState, RuntimePolicySnapshot, StateStore, UpdateJournal


@dataclass(frozen=True)
class RuntimeStatus:
    lab_id: str
    state: str
    url: str
    run_id: str
    requested_reference: str
    resolved_digest: str
    trust_level: str
    trusted_run: bool
    lock_match: bool
    resources: tuple[dict[str, str], ...]


@dataclass(frozen=True)
class RuntimeUpdate:
    lab_id: str
    outcome: str
    previous_manifest_identity: str
    candidate_manifest_identity: str
    previous_run_id: str
    active_run_id: str
    status: RuntimeStatus


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _open_local_health(request: urllib.request.Request, *, timeout: float) -> Any:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    return opener.open(request, timeout=timeout)


def _temporary_loopback_port(excluded: int) -> int:
    try:
        for _ in range(8):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = int(sock.getsockname()[1])
            if port != excluded:
                return port
    except OSError as exc:
        raise PreflightError(f"could not reserve a temporary loopback port: {exc}") from exc
    raise PreflightError("could not reserve a distinct temporary loopback update port")


def _resource_limits(lab: ReviewedLab) -> tuple[int, float, int, bool]:
    raw = lab.manifest.raw["resources"]
    if not isinstance(raw, dict):
        raise IntegrityError("manifest resources are malformed")
    memory = raw.get("memory_mb")
    cpus = raw.get("cpus")
    pids = raw.get("pids")
    read_only = raw.get("read_only_root")
    if (
        not isinstance(memory, int)
        or isinstance(memory, bool)
        or not 128 <= memory <= 16384
        or not isinstance(cpus, int | float)
        or isinstance(cpus, bool)
        or not 0.1 <= float(cpus) <= 8
        or not isinstance(pids, int)
        or isinstance(pids, bool)
        or not 16 <= pids <= 4096
        or not isinstance(read_only, bool)
    ):
        raise IntegrityError("manifest resource limits are missing or unsafe")
    if not read_only:
        raise PolicyError("runnable application root filesystem must be read-only")
    return memory, float(cpus), pids, read_only


def _runtime_policy(lab: ReviewedLab) -> RuntimePolicySnapshot:
    memory, cpus, pids, read_only = _resource_limits(lab)
    timeout = lab.manifest.raw["health_check"]["timeout_seconds"]
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise IntegrityError("manifest health-check timeout is malformed")
    return RuntimePolicySnapshot(
        memory,
        cpus,
        pids,
        read_only,
        lab.manifest.outbound_required,
        lab.manifest.ephemeral_storage,
        lab.manifest.friendly_hostname,
        timeout,
        lab.manifest.services,
        lab.manifest.persistence_required,
    )


def _application_image(lab: ReviewedLab) -> Image:
    values = [image for image in lab.manifest.images if image.role == "application"]
    if len(values) != 1:
        raise IntegrityError("adapter must define exactly one application image")
    return values[0]


def _gateway_image(lab: ReviewedLab) -> Image:
    values = [image for image in lab.manifest.images if image.role == "gateway"]
    if len(values) != 1:
        raise IntegrityError("runnable adapter must define exactly one reviewed gateway image")
    return values[0]


class Runtime:
    def __init__(
        self,
        catalogue: Catalogue | None = None,
        paths: Paths | None = None,
        docker: Docker | None = None,
        *,
        sleeper: Callable[[float], None] = time.sleep,
        temporary_port_selector: Callable[[int], int] = _temporary_loopback_port,
    ) -> None:
        self.catalogue = catalogue or Catalogue()
        self.paths = paths or Paths.discover()
        self.store = StateStore(self.paths)
        self.docker = docker or Docker()
        self.sleeper = sleeper
        self.temporary_port_selector = temporary_port_selector
        self._thread_lock = threading.RLock()
        self._lock_depth = 0

    @contextlib.contextmanager
    def _lifecycle(self) -> Iterator[None]:
        with self._thread_lock:
            if self._lock_depth:
                self._lock_depth += 1
                try:
                    yield
                finally:
                    self._lock_depth -= 1
                return
            self.paths.ensure()
            timeout = min(max(self.docker.timeouts.inspect, 1), 60)
            with self.store.lifecycle_lock(timeout=timeout):
                self._lock_depth = 1
                try:
                    yield
                finally:
                    self._lock_depth = 0

    @staticmethod
    def url(lab: ReviewedLab, port: int) -> str:
        suffix = "" if port == 80 else f":{port}"
        return f"http://{lab.manifest.friendly_hostname}{suffix}"

    @staticmethod
    def local_url(port: int, path: str) -> str:
        return f"http://127.0.0.1:{port}{path}"

    def _require_runnable(self, lab: ReviewedLab) -> None:
        if lab.manifest.adapter_status is not AdapterStatus.RUNNABLE:
            raise PolicyError(
                f"{lab.manifest.id} is {lab.manifest.adapter_status}: {lab.manifest.status_reason}"
            )

    def _preflight_lab(self, lab: ReviewedLab) -> str:
        detail = self.docker.preflight()
        if detail.get("isolated_networking") is not True:
            server_version = detail.get("engine", "unknown")
            raise PreflightError(
                f"Docker Engine {MINIMUM_ENGINE_TEXT} or newer is required for isolated "
                f"VulnDockyard lab networking; server reports {server_version}"
            )
        local_platform = detail.get("platform")
        if not isinstance(local_platform, str):
            raise IntegrityError("Docker preflight did not report a validated local platform")
        unavailable = [
            image.role for image in lab.manifest.images if local_platform not in image.architectures
        ]
        if unavailable:
            raise PreflightError(
                f"{lab.manifest.id} does not support {local_platform} for required image roles: "
                f"{', '.join(unavailable)}"
            )
        if local_platform not in lab.manifest.verification_platforms:
            raise PreflightError(
                f"{lab.manifest.id} has no reviewed smoke-test evidence for {local_platform}"
            )
        return local_platform

    def pull(self, lab: ReviewedLab) -> tuple[str, ...]:
        self._require_runnable(lab)
        self._preflight_lab(lab)
        references = tuple(image.reference for image in lab.manifest.images)
        for reference in references:
            self.docker.pull(reference)
        return references

    @staticmethod
    def _validate_candidate(lab: ReviewedLab) -> None:
        if lab.manifest.adapter_status is not AdapterStatus.RUNNABLE:
            raise PolicyError(f"{lab.manifest.id} has no runnable reviewed update candidate")
        if identity(lab.manifest.raw) != lab.manifest_identity:
            raise IntegrityError("reviewed update candidate manifest identity does not match")
        if lab.manifest.images != lab.lock.images:
            raise IntegrityError("reviewed update candidate images do not match its immutable lock")
        if template_identity(lab.manifest) != lab.lock.template_sha256:
            raise IntegrityError("reviewed update candidate orchestration does not match its lock")
        if not re.fullmatch(r"[0-9a-f]{64}", lab.manifest_identity):
            raise IntegrityError("reviewed update candidate identity is malformed")
        if lab.manifest.outbound_required:
            raise PolicyError(
                "reviewed update candidate requires an explicit egress acknowledgement; "
                "activate it with an explicit start instead"
            )
        for image in lab.manifest.images:
            if OCI_NAME.fullmatch(image.name) is None or DIGEST.fullmatch(image.digest) is None:
                raise IntegrityError("reviewed update candidate contains an unsafe image reference")

    def _assert_single_lab(self, lab_id: str, allow_multiple: bool) -> None:
        if allow_multiple:
            return
        states = self.store.all()
        managed = self.docker.managed_resources()
        records = tuple(record for state in states for record in state.resources)
        unknown = [
            f"{kind}:{object_id}"
            for kind in ("container", "network", "volume")
            for object_id in managed[kind]
            if not any(record.kind == kind and record.object_id == object_id for record in records)
        ]
        if unknown:
            raise PolicyError(
                "unrecorded managed Docker resources prevent single-lab startup; "
                f"ownership cannot be inferred ({', '.join(unknown)})"
            )
        others = [state.lab_id for state in states if state.lab_id != lab_id]
        if others:
            raise PolicyError(
                "another lab has managed runtime state; use --allow-multiple only after reviewing "
                f"isolation trade-offs: {', '.join(others)}"
            )

    def _validate_state(
        self,
        state: RunState,
        *,
        current_identity: str | None = None,
        lab: ReviewedLab | None = None,
        repair_missing_networks: bool = False,
        enforce_policy: bool = False,
    ) -> tuple[dict[str, Any], ...]:
        if current_identity is not None and state.manifest_identity != current_identity:
            raise PolicyError(
                "existing state belongs to a different reviewed manifest; remove it explicitly"
            )
        ownership = Ownership.from_state(state)
        inspections = tuple(
            self.docker.validate_owned(record, ownership) for record in state.resources
        )
        policy = state.runtime_policy if enforce_policy else None
        if lab is not None and state.manifest_identity == lab.manifest_identity:
            reviewed_policy = _runtime_policy(lab)
            if policy is not None and policy != reviewed_policy:
                raise PolicyError("runtime policy snapshot differs from the reviewed manifest")
            policy = reviewed_policy
        if policy is not None:
            prefix = f"vdy-{state.lab_id}-{state.run_id[:12]}"
            storage = policy.ephemeral_storage
            named_storage = (
                storage.seeded + storage.empty if policy.persistence_required else storage.seeded
            )
            mounts = {f"{prefix}-volume-{mount.name}": mount for mount in named_storage}
            volumes = [record for record in state.resources if record.kind == "volume"]
            actual_volume_names = {record.name for record in volumes}
            exact_storage_required = state.runtime_policy is not None
            if (
                len(volumes) != len(actual_volume_names)
                or not actual_volume_names.issubset(mounts)
                or (exact_storage_required and actual_volume_names != set(mounts))
            ):
                raise PolicyError("managed runtime named storage differs from the reviewed policy")
            for record in volumes:
                if policy.persistence_required:
                    self.docker.validate_persistent_volume(record, ownership)
                else:
                    self.docker.validate_ephemeral_volume(
                        record,
                        ownership,
                        mounts[record.name],
                        uid=storage.uid,
                        gid=storage.gid,
                    )
            records_by_name = {record.name: record for record in state.resources}
            inspections_by_name = {
                record.name: inspection
                for record, inspection in zip(state.resources, inspections, strict=True)
            }
            for suffix, expected_internal in (("net", True), ("ingress", False)):
                name = f"{prefix}-{suffix}"
                if name in inspections_by_name:
                    self.docker.validate_network_policy(
                        inspections_by_name[name], internal=expected_internal
                    )
            app_name = f"{prefix}-app"
            if app_name in inspections_by_name:
                if actual_volume_names != set(mounts):
                    raise PolicyError(
                        "managed application lacks its complete reviewed storage inventory"
                    )
                self.docker.validate_application_policy(
                    inspections_by_name[app_name],
                    image=state.requested_reference,
                    network=f"{prefix}-net",
                    memory_mb=policy.memory_mb,
                    cpus=policy.cpus,
                    pids=policy.pids,
                    seeded_mounts=tuple(
                        (records_by_name[name], mount) for name, mount in mounts.items()
                    ),
                    empty_mounts=() if policy.persistence_required else storage.empty,
                    storage_uid=storage.uid,
                    storage_gid=storage.gid,
                )
            gateway_name = f"{prefix}-gateway"
            if gateway_name in inspections_by_name:
                if state.gateway_reference is None or state.upstream_port is None:
                    raise PolicyError("managed runtime lacks its gateway rollback snapshot")
                self.docker.validate_gateway_policy(
                    inspections_by_name[gateway_name],
                    image=state.gateway_reference,
                    network=f"{prefix}-ingress",
                    upstream_port=state.upstream_port,
                    host_port=state.host_port,
                )

            app_record = records_by_name.get(app_name)
            gateway_record = records_by_name.get(gateway_name)
            internal = records_by_name.get(f"{prefix}-net")
            ingress = records_by_name.get(f"{prefix}-ingress")
            expected_by_container: tuple[
                tuple[ResourceRecord | None, tuple[ResourceRecord | None, ...]], ...
            ] = (
                (
                    app_record,
                    (internal, ingress) if policy.outbound_required else (internal,),
                ),
                (gateway_record, (ingress, internal)),
            )
            for container, expected_values in expected_by_container:
                if container is None:
                    continue
                if any(network is None for network in expected_values):
                    raise PolicyError("managed runtime lacks a required network record")
                expected_networks = {
                    network.name: network.object_id
                    for network in expected_values
                    if network is not None
                }
                actual_networks = self.docker.container_networks(
                    inspections_by_name[container.name]
                )
                unexpected_networks = set(actual_networks).difference(expected_networks)
                wrong_identities = {
                    name
                    for name in actual_networks.keys() & expected_networks.keys()
                    if actual_networks[name] and actual_networks[name] != expected_networks[name]
                }
                if unexpected_networks or wrong_identities:
                    raise PolicyError("managed container has an unreviewed network attachment")
                missing_networks = set(expected_networks).difference(actual_networks)
                if missing_networks and not repair_missing_networks:
                    raise PolicyError("managed container lost a required network attachment")
                for name in sorted(missing_networks):
                    network = records_by_name[name]
                    self._ensure_network_connected(network, container)

            expected_endpoints = {
                f"{prefix}-net": {
                    record.object_id
                    for record in (app_record, gateway_record)
                    if record is not None and self._running(inspections_by_name[record.name])
                },
                f"{prefix}-ingress": {
                    record.object_id
                    for record in (
                        gateway_record,
                        app_record if policy.outbound_required else None,
                    )
                    if record is not None and self._running(inspections_by_name[record.name])
                },
            }
            for name, expected_container_ids in expected_endpoints.items():
                endpoint_network = records_by_name.get(name)
                if endpoint_network is None:
                    continue
                inspection = self.docker.validate_owned(endpoint_network, ownership)
                self.docker.validate_network_endpoints(
                    inspection, expected_container_ids=expected_container_ids
                )
            expected_configured_consumers = {
                f"{prefix}-net": {
                    record.object_id
                    for record in (app_record, gateway_record)
                    if record is not None
                },
                f"{prefix}-ingress": {
                    record.object_id
                    for record in (
                        gateway_record,
                        app_record if policy.outbound_required else None,
                    )
                    if record is not None
                },
            }
            for name, expected_container_ids in expected_configured_consumers.items():
                configured_network = records_by_name.get(name)
                if configured_network is None:
                    continue
                actual_container_ids = self.docker.configured_network_consumers(configured_network)
                if actual_container_ids != expected_container_ids:
                    raise PolicyError(
                        "Docker network configured consumers differ from the exact managed topology"
                    )
        return inspections

    def _assert_no_orphans(
        self,
        lab_id: str,
        state: RunState | None = None,
        *,
        coexisting: tuple[RunState, ...] = (),
    ) -> None:
        managed = self.docker.managed_resources(lab_id=lab_id)
        recorded = tuple(
            record
            for current in ((state,) if state is not None else ()) + coexisting
            for record in current.resources
        )
        descriptions = [
            f"{kind}:{object_id}"
            for kind in ("container", "network", "volume")
            for object_id in managed[kind]
            if not any(record.kind == kind and object_id == record.object_id for record in recorded)
        ]
        if descriptions:
            raise PolicyError(
                "managed Docker resources exist without usable runtime state; refusing to infer "
                f"ownership for cleanup ({', '.join(descriptions)})"
            )

    def _health(self, lab: ReviewedLab, port: int) -> None:
        self._health_snapshot(_runtime_policy(lab), port)

    def _health_snapshot(self, policy: RuntimePolicySnapshot, port: int) -> None:
        health_timeout = min(self.docker.timeouts.health, float(policy.health_timeout_seconds))
        deadline = time.monotonic() + health_timeout
        for service in policy.services:
            identity = service.identity_marker
            last_error = "not attempted"
            request = urllib.request.Request(  # noqa: S310 - local http URL only
                self.local_url(port, service.health_path),
                headers={
                    "Host": policy.friendly_hostname,
                    "User-Agent": "VulnDockyard/1",
                },
                method="GET",
            )
            while time.monotonic() < deadline:
                try:
                    with _open_local_health(request, timeout=min(3.0, health_timeout)) as response:
                        if response.geturl() != request.full_url:
                            raise IntegrityError("health response escaped its fixed loopback URL")
                        body = response.read(262_145)
                        if len(body) > 262_144:
                            raise IntegrityError("health response exceeded 256 KiB")
                        text = body.decode("utf-8", "replace")
                        if identity.casefold() in text.casefold():
                            break
                        last_error = f"identity marker {identity!r} was absent"
                except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                    last_error = str(exc)
                self.sleeper(0.5)
            else:
                raise PreflightError(
                    "readiness and identity verification timed out for "
                    f"{service.name}: {last_error}"
                )

    def _running(self, inspection: dict[str, Any]) -> bool:
        value = inspection.get("State", {}).get("Running")
        if not isinstance(value, bool):
            raise IntegrityError("Docker container state is malformed")
        return value

    def _ensure_network_connected(self, network: ResourceRecord, container: ResourceRecord) -> None:
        if self.docker.network_connected(network, container):
            return
        self.docker.connect_network(network, container)
        if not self.docker.network_connected(network, container):
            raise IntegrityError("Docker did not establish the exact requested network attachment")

    def _complete_layout(
        self,
        lab: ReviewedLab,
        state: RunState,
        inspections: tuple[dict[str, Any], ...],
    ) -> bool:
        kinds = [record.kind for record in state.resources]
        container_roles = {
            self.docker._labels(record.kind, inspection).get(ROLE)
            for record, inspection in zip(state.resources, inspections, strict=True)
            if record.kind == "container"
        }
        volume_roles = {
            self.docker._labels(record.kind, inspection).get(ROLE)
            for record, inspection in zip(state.resources, inspections, strict=True)
            if record.kind == "volume"
        }
        policy = state.runtime_policy
        if policy is None and state.manifest_identity == lab.manifest_identity:
            policy = _runtime_policy(lab)
        expected_volume_roles = (
            {
                f"volume-{mount.name}"
                for mount in (
                    policy.ephemeral_storage.seeded + policy.ephemeral_storage.empty
                    if policy.persistence_required
                    else policy.ephemeral_storage.seeded
                )
            }
            if policy is not None
            else set()
        )
        storage_matches = policy is not None and volume_roles == expected_volume_roles
        return (
            kinds.count("container") == 2
            and kinds.count("network") == 2
            and kinds.count("volume") == len(volume_roles)
            and container_roles == {"application", "gateway"}
            and storage_matches
        )

    def _wait_for_seeder(self, seeder: ResourceRecord, ownership: Ownership) -> None:
        deadline = time.monotonic() + self.docker.timeouts.start
        last_output = ""
        while time.monotonic() < deadline:
            inspection = self.docker.validate_owned(seeder, ownership)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            result = self.docker.read_logs(
                seeder, timeout=min(remaining, self.docker.timeouts.inspect), tail=20
            )
            lines = tuple((result.stdout + result.stderr).splitlines())
            if SEED_READY_MARKER in lines:
                if not self._running(inspection):
                    raise PreflightError(
                        "ephemeral storage seeder exited after reporting readiness"
                    )
                return
            last_output = " | ".join(lines[-3:])
            if not self._running(inspection):
                raise PreflightError(
                    "ephemeral storage seeder exited before its exact readiness marker"
                    + (f": {last_output}" if last_output else "")
                )
            self.sleeper(min(0.1, max(remaining, 0)))
        raise PreflightError(
            "ephemeral storage seeder readiness timed out"
            + (f": {last_output}" if last_output else "")
        )

    def _reseed_and_start(
        self,
        lab: ReviewedLab,
        state: RunState,
        inspections: tuple[dict[str, Any], ...],
        *,
        start_gateway: bool = True,
        on_checkpoint: Callable[[RunState], None] | None = None,
    ) -> None:
        """Restore tmpfs-backed seed data before restarting a stopped application."""
        ownership = Ownership.from_state(state)
        policy = state.runtime_policy
        if policy is None and state.manifest_identity == lab.manifest_identity:
            policy = _runtime_policy(lab)
        if policy is None:
            raise PolicyError("runtime lacks the storage policy required for safe reseeding")
        storage = policy.ephemeral_storage
        prefix = f"vdy-{state.lab_id}-{state.run_id[:12]}"
        volumes = {record.name: record for record in state.resources if record.kind == "volume"}
        seeded_mounts = (
            ()
            if policy.persistence_required
            else tuple(
                (volumes[f"{prefix}-volume-{mount.name}"], mount) for mount in storage.seeded
            )
        )
        containers = {
            self.docker._labels(record.kind, inspection).get(ROLE): record
            for record, inspection in zip(state.resources, inspections, strict=True)
            if record.kind == "container"
        }
        application = containers.get("application")
        gateway = containers.get("gateway")
        if application is None or gateway is None:
            raise IntegrityError("managed runtime lacks its application or gateway container")

        def checkpoint(current: RunState) -> None:
            self.store.save(current)
            if on_checkpoint is not None:
                on_checkpoint(current)

        seeder: ResourceRecord | None = None
        try:
            if seeded_mounts:
                seeder = self.docker.create_seeder(
                    name=f"{prefix}-seeder",
                    image=state.requested_reference,
                    ownership=ownership,
                    seeded_mounts=seeded_mounts,
                    uid=storage.uid,
                    gid=storage.gid,
                )
                checkpoint(replace(state, resources=(*state.resources, seeder)))
                self.docker.start(seeder)
                checkpoint(replace(state, resources=(*state.resources, seeder)))
                self._wait_for_seeder(seeder, ownership)
                if not self._running(self.docker.validate_owned(seeder, ownership)):
                    raise PreflightError(
                        "ephemeral storage seeder stopped before application start"
                    )
            self.docker.start(application)
            if not self._running(self.docker.validate_owned(application, ownership)):
                raise PreflightError("application did not remain running after Docker start")
            if seeder is not None:
                if not self._running(self.docker.validate_owned(seeder, ownership)):
                    raise PreflightError(
                        "ephemeral storage seeder stopped while application started"
                    )
                self.docker.remove(seeder)
                seeder = None
                checkpoint(state)
            if start_gateway:
                self.docker.start(gateway)
            checkpoint(state)
        except BaseException:
            for record in (gateway, application):
                with contextlib.suppress(Exception):
                    if self.docker.exists(record.kind, record.object_id):
                        inspection = self.docker.validate_owned(record, ownership)
                        if self._running(inspection):
                            self.docker.stop(record)
            if seeder is not None:
                with contextlib.suppress(Exception):
                    if self.docker.exists(seeder.kind, seeder.object_id):
                        self.docker.validate_owned(seeder, ownership)
                        self.docker.remove(seeder)
            checkpoint(state)
            raise

    def _create_run(
        self,
        lab: ReviewedLab,
        *,
        host_port: int,
        selected_reference: str,
        trusted: bool,
        persist: bool,
        coexisting: tuple[RunState, ...] = (),
        run_id: str | None = None,
        created_at: str | None = None,
        on_checkpoint: Callable[[RunState], None] | None = None,
    ) -> RunState:
        gateway = _gateway_image(lab)
        memory, cpus, pids, read_only = _resource_limits(lab)
        storage = lab.manifest.ephemeral_storage
        run_id = run_id or uuid.uuid4().hex
        created_at = created_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ownership = Ownership(lab.manifest.id, lab.manifest_identity, run_id, created_at, trusted)
        prefix = f"vdy-{lab.manifest.id}-{run_id[:12]}"
        resources: list[ResourceRecord] = []

        def snapshot() -> RunState:
            return RunState.create(
                lab_id=lab.manifest.id,
                run_id=run_id,
                manifest_identity=lab.manifest_identity,
                host_port=host_port,
                trusted=trusted,
                requested_reference=selected_reference,
                resolved_digest=selected_reference.rsplit("@", 1)[-1],
                resources=tuple(resources),
                gateway_reference=gateway.reference,
                upstream_port=lab.manifest.services[0].internal_port,
                runtime_policy=_runtime_policy(lab),
                created_at=created_at,
            )

        def checkpoint() -> RunState:
            current = snapshot()
            if persist:
                self.store.save(current)
            if on_checkpoint is not None:
                on_checkpoint(current)
            return current

        checkpoint()
        try:
            network = self.docker.create_network(f"{prefix}-net", ownership, internal=True)
            resources.append(network)
            checkpoint()
            ingress = self.docker.create_network(f"{prefix}-ingress", ownership, internal=False)
            resources.append(ingress)
            checkpoint()
            volume_mounts: list[tuple[ResourceRecord, EphemeralMount]] = []
            seeded_mounts: list[tuple[ResourceRecord, EphemeralMount]] = []
            named_storage = (
                storage.seeded + storage.empty
                if lab.manifest.persistence_required
                else storage.seeded
            )
            seeded_names = {mount.name for mount in storage.seeded}
            for mount in named_storage:
                volume = (
                    self.docker.create_persistent_volume(
                        name=f"{prefix}-volume-{mount.name}", ownership=ownership
                    )
                    if lab.manifest.persistence_required
                    else self.docker.create_ephemeral_volume(
                        name=f"{prefix}-volume-{mount.name}",
                        mount=mount,
                        ownership=ownership,
                        uid=storage.uid,
                        gid=storage.gid,
                    )
                )
                resources.append(volume)
                volume_mounts.append((volume, mount))
                if mount.name in seeded_names:
                    seeded_mounts.append((volume, mount))
                checkpoint()
            seeder: ResourceRecord | None = None
            if seeded_mounts:
                seeder = self.docker.create_seeder(
                    name=f"{prefix}-seeder",
                    image=selected_reference,
                    ownership=ownership,
                    seeded_mounts=tuple(seeded_mounts),
                    uid=storage.uid,
                    gid=storage.gid,
                )
                resources.append(seeder)
                checkpoint()
                self.docker.start(seeder)
                checkpoint()
                self._wait_for_seeder(seeder, ownership)
            application = self.docker.create_application(
                name=f"{prefix}-app",
                image=selected_reference,
                network=network.name,
                ownership=ownership,
                memory_mb=memory,
                cpus=cpus,
                pids=pids,
                read_only=read_only,
                seeded_mounts=tuple(volume_mounts),
                empty_mounts=() if lab.manifest.persistence_required else storage.empty,
                storage_uid=storage.uid,
                storage_gid=storage.gid,
            )
            resources.append(application)
            checkpoint()
            service = lab.manifest.services[0]
            gateway_record = self.docker.create_gateway(
                name=f"{prefix}-gateway",
                image=gateway.reference,
                network=ingress.name,
                upstream_port=service.internal_port,
                host_port=host_port,
                ownership=ownership,
            )
            resources.append(gateway_record)
            state = checkpoint()
            self._ensure_network_connected(network, gateway_record)
            if lab.manifest.outbound_required:
                # Egress remains available only through the reviewed ingress network.
                self._ensure_network_connected(ingress, application)
            if seeder is not None and not self._running(
                self.docker.validate_owned(seeder, ownership)
            ):
                raise PreflightError("ephemeral storage seeder stopped before application start")
            self.docker.start(application)
            if not self._running(self.docker.validate_owned(application, ownership)):
                raise PreflightError("application did not remain running after Docker start")
            checkpoint()
            if seeder is not None:
                if not self._running(self.docker.validate_owned(seeder, ownership)):
                    raise PreflightError(
                        "ephemeral storage seeder stopped while application started"
                    )
                self.docker.remove(seeder)
                resources.remove(seeder)
                checkpoint()
            self.docker.start(gateway_record)
            state = checkpoint()
            self._health(lab, host_port)
            inspections = self._validate_state(state, lab=lab, enforce_policy=True)
            if not self._complete_layout(lab, state, inspections):
                raise IntegrityError("new runtime failed its exact steady-state layout check")
        except BaseException:
            # Cover the narrow create-to-checkpoint window: an exact managed
            # object may exist even when its create call never returned to append
            # the ID. Adoption still requires deterministic name and all labels.
            cleanup_state = self._adopt_journaled_candidate(lab, snapshot())
            if cleanup_state.resources:
                if persist:
                    self.store.save(cleanup_state)
                if on_checkpoint is not None:
                    on_checkpoint(cleanup_state)
                try:
                    self._cleanup(cleanup_state, coexisting=coexisting)
                except Exception:
                    # Persistent state, or the preserved prior state for a candidate,
                    # remains available for an explicit bounded recovery attempt.
                    raise
                else:
                    if persist:
                        self.store.delete(lab.manifest.id)
            raise
        return state

    def up(
        self,
        lab: ReviewedLab,
        *,
        host_port: int = 80,
        allow_multiple: bool = False,
        acknowledge_egress: bool = False,
        unsafe_image: str | None = None,
        unsafe_development: bool = False,
    ) -> RuntimeStatus:
        with self._lifecycle():
            self._require_runnable(lab)
            self._preflight_lab(lab)
            self._recover_update(lab)
            return self._up(
                lab,
                host_port=host_port,
                allow_multiple=allow_multiple,
                acknowledge_egress=acknowledge_egress,
                unsafe_image=unsafe_image,
                unsafe_development=unsafe_development,
            )

    def _up(
        self,
        lab: ReviewedLab,
        *,
        host_port: int = 80,
        allow_multiple: bool = False,
        acknowledge_egress: bool = False,
        unsafe_image: str | None = None,
        unsafe_development: bool = False,
    ) -> RuntimeStatus:
        self._require_runnable(lab)
        if (
            not isinstance(host_port, int)
            or isinstance(host_port, bool)
            or not 1 <= host_port <= 65535
        ):
            raise PolicyError("host port must be between 1 and 65535")
        if lab.manifest.outbound_required and not acknowledge_egress:
            raise PolicyError(
                "this lab requires outbound connectivity; repeat with --acknowledge-egress"
            )
        if unsafe_image is not None:
            if not unsafe_development:
                raise PolicyError(
                    "--unsafe-image requires --unsafe-development and produces an untrusted run"
                )
            try:
                unsafe_name, unsafe_digest = unsafe_image.rsplit("@", 1)
            except ValueError:
                unsafe_name, unsafe_digest = "", ""
            if OCI_NAME.fullmatch(unsafe_name) is None or DIGEST.fullmatch(unsafe_digest) is None:
                raise PolicyError(
                    "unsafe development images must still use an immutable sha256 digest"
                )
        self.paths.ensure()
        self._preflight_lab(lab)
        existing = self.store.load(lab.manifest.id)
        if existing is not None and existing.phase == "rebuild":
            return self._resume_persistent_rebuild(lab, existing)
        if existing is not None and existing.manifest_identity == lab.manifest_identity:
            # A process may be terminated after Docker creates an exact managed
            # object but before the following atomic state checkpoint. Recover only
            # deterministic names with the complete journaled ownership identity.
            adopted = self._adopt_journaled_candidate(lab, existing)
            if adopted != existing:
                self.store.save(adopted)
                existing = adopted
            existing, discarded_seeder = self._discard_rollback_seeder(existing)
            if discarded_seeder:
                self.store.save(existing)
        self._assert_single_lab(lab.manifest.id, allow_multiple)
        self._assert_no_orphans(lab.manifest.id, existing)
        if existing is not None:
            if existing.manifest_identity != lab.manifest_identity:
                raise PolicyError(
                    "existing state belongs to a different reviewed manifest; remove it explicitly"
                )
            missing = any(
                not self.docker.exists(record.kind, record.object_id)
                for record in existing.resources
            )
            missing_persistent_volume = (
                existing.runtime_policy is not None
                and existing.runtime_policy.persistence_required
                and any(
                    record.kind == "volume"
                    and not self.docker.exists(record.kind, record.object_id)
                    for record in existing.resources
                )
            )
            if missing_persistent_volume:
                raise PolicyError(
                    "persistent runtime volume is missing; refusing automatic cleanup or repair"
                )
            inspections = (
                ()
                if missing
                else self._validate_state(
                    existing,
                    current_identity=lab.manifest_identity,
                    lab=lab,
                    repair_missing_networks=True,
                )
            )
            if missing or not self._complete_layout(lab, existing, inspections):
                if (
                    existing.runtime_policy is not None
                    and existing.runtime_policy.persistence_required
                ):
                    self._validate_persistent_rebuild_resources(existing, existing.runtime_policy)
                    rebuilding = replace(existing, phase="rebuild")
                    self.store.save(rebuilding)
                    return self._resume_persistent_rebuild(lab, rebuilding)
                self._cleanup(existing)
                self.store.delete(lab.manifest.id)
                existing = None
        if existing is not None:
            if not existing.trusted and not unsafe_development:
                raise PolicyError(
                    "the preserved runtime is an untrusted development run; "
                    "repeat with --unsafe-development or remove it explicitly"
                )
            if unsafe_image is not None and (
                existing.trusted or existing.requested_reference != unsafe_image
            ):
                raise PolicyError(
                    "the requested unsafe image does not match the preserved untrusted runtime; "
                    "remove it explicitly before changing image or trust state"
                )
            container_pairs = [
                (record, inspection)
                for record, inspection in zip(existing.resources, inspections, strict=True)
                if record.kind == "container"
            ]
            if all(self._running(inspection) for _, inspection in container_pairs):
                return self._status(lab)
            running_by_role = {
                self.docker._labels(record.kind, inspection).get(ROLE): self._running(inspection)
                for record, inspection in container_pairs
            }
            try:
                if running_by_role.get("application") is False:
                    if running_by_role.get("gateway") is True:
                        gateway_record = next(
                            record
                            for record, inspection in container_pairs
                            if self.docker._labels(record.kind, inspection).get(ROLE) == "gateway"
                        )
                        self.docker.stop(gateway_record)
                    self._reseed_and_start(lab, existing, inspections)
                else:
                    for record, inspection in container_pairs:
                        if not self._running(inspection):
                            self.docker.start(record)
                self._health(lab, existing.host_port)
            except BaseException:
                for record, _ in reversed(container_pairs):
                    with contextlib.suppress(Exception):
                        self.docker.stop(record)
                raise
            return self._status(lab)

        app = _application_image(lab)
        gateway = _gateway_image(lab)
        selected_reference = unsafe_image or app.reference
        trusted = unsafe_image is None
        # Pull every reviewed support image; an unsafe app never lends its run reviewed trust.
        self.docker.pull(selected_reference)
        self.docker.pull(gateway.reference)
        self._create_run(
            lab,
            host_port=host_port,
            selected_reference=selected_reference,
            trusted=trusted,
            persist=True,
        )
        return self._status(lab)

    def status(self, lab: ReviewedLab) -> RuntimeStatus:
        with self._lifecycle():
            self._refuse_pending_update_for_observation(lab)
            return self._status(lab)

    def _status(self, lab: ReviewedLab) -> RuntimeStatus:
        state = self.store.load(lab.manifest.id)
        if state is None:
            return RuntimeStatus(
                lab.manifest.id,
                "absent",
                self.url(lab, 80),
                "",
                "",
                "",
                lab.manifest.trust.value,
                False,
                False,
                (),
            )
        self._assert_no_orphans(lab.manifest.id, state)
        return self._status_from_state(lab, state)

    def _status_from_state(self, lab: ReviewedLab, state: RunState) -> RuntimeStatus:
        inspections = self._validate_state(state, lab=lab, enforce_policy=True)
        resource_status: list[dict[str, str]] = []
        running_values: list[bool] = []
        actual_images: dict[str, str] = {}
        for record, inspection in zip(state.resources, inspections, strict=True):
            item = {"kind": record.kind, "name": record.name, "id": record.object_id}
            labels = self.docker._labels(record.kind, inspection)
            item["role"] = labels.get(ROLE, "unknown")
            if record.kind == "container":
                running = self._running(inspection)
                running_values.append(running)
                item["state"] = "running" if running else "stopped"
                role = labels.get(ROLE, "unknown")
                image = inspection.get("Config", {}).get("Image")
                if not isinstance(image, str):
                    raise IntegrityError("Docker container image identity is malformed")
                if role in actual_images:
                    raise IntegrityError("managed runtime contains a duplicate container role")
                actual_images[role] = image
                bindings = inspection.get("HostConfig", {}).get("PortBindings")
                if role == "application" and bindings not in ({}, None):
                    raise IntegrityError("application container unexpectedly publishes ports")
                if role == "gateway" and bindings != {
                    "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(state.host_port)}]
                }:
                    raise IntegrityError("gateway container has an unexpected port binding")
            resource_status.append(item)
        complete = self._complete_layout(lab, state, inspections)
        if running_values and all(running_values) and complete:
            lifecycle = "running"
        elif any(running_values) or not complete:
            lifecycle = "degraded"
        else:
            lifecycle = "stopped"
        expected_images = {
            image.role: image.reference
            for image in lab.lock.images
            if image.role in {"application", "gateway"}
        }
        application = _application_image(lab)
        gateway = _gateway_image(lab)
        trust_level = lab.manifest.trust.value if state.trusted else "untrusted-development"
        return RuntimeStatus(
            lab.manifest.id,
            lifecycle,
            self.url(lab, state.host_port),
            state.run_id,
            state.requested_reference,
            state.resolved_digest,
            trust_level,
            state.trusted,
            state.trusted
            and state.manifest_identity == lab.manifest_identity
            and state.requested_reference == application.reference
            and state.resolved_digest == application.digest
            and state.gateway_reference == gateway.reference
            and actual_images == expected_images,
            tuple(resource_status),
        )

    def _adopt_journaled_candidate(self, lab: ReviewedLab, state: RunState) -> RunState:
        """Adopt only exact intended names with every journaled ownership label."""
        policy = state.runtime_policy
        if policy is None and state.manifest_identity == lab.manifest_identity:
            policy = _runtime_policy(lab)
        if policy is None:
            raise PolicyError("journaled runtime lacks its containment policy snapshot")
        ownership = Ownership.from_state(state)
        prefix = f"vdy-{state.lab_id}-{state.run_id[:12]}"
        expected = (
            ("network", f"{prefix}-net"),
            ("network", f"{prefix}-ingress"),
            *(
                ("volume", f"{prefix}-volume-{mount.name}")
                for mount in (
                    policy.ephemeral_storage.seeded + policy.ephemeral_storage.empty
                    if policy.persistence_required
                    else policy.ephemeral_storage.seeded
                )
            ),
            ("container", f"{prefix}-seeder"),
            ("container", f"{prefix}-app"),
            ("container", f"{prefix}-gateway"),
        )
        expected_set = set(expected)
        records = [
            record
            for record in state.resources
            if self.docker.exists(record.kind, record.object_id)
        ]
        names = {(record.kind, record.name) for record in records}
        managed = self.docker.managed_resources(lab_id=state.lab_id)
        recorded_ids = {(record.kind, record.object_id) for record in records}
        for kind in ("network", "volume", "container"):
            for object_id in managed[kind]:
                if (kind, object_id) in recorded_ids:
                    continue
                # Discovery is only a hint.  Require an exact currently existing
                # identifier before inspecting it so a shortened/ambiguous Docker
                # ID can never be adopted as owned state.
                if not self.docker.exists(kind, object_id):
                    continue
                inspection = self.docker.inspect(kind, object_id)
                raw_name = inspection.get("Name")
                name = raw_name.removeprefix("/") if isinstance(raw_name, str) else ""
                if (kind, name) not in expected_set or (kind, name) in names:
                    continue
                record = ResourceRecord(kind, name, object_id)
                self.docker.validate_owned(record, ownership)
                if kind == "volume":
                    storage_name = name.removeprefix(f"{prefix}-volume-")
                    mount = next(
                        value
                        for value in (
                            policy.ephemeral_storage.seeded + policy.ephemeral_storage.empty
                            if policy.persistence_required
                            else policy.ephemeral_storage.seeded
                        )
                        if value.name == storage_name
                    )
                    if policy.persistence_required:
                        self.docker.validate_persistent_volume(record, ownership)
                    else:
                        self.docker.validate_ephemeral_volume(
                            record,
                            ownership,
                            mount,
                            uid=policy.ephemeral_storage.uid,
                            gid=policy.ephemeral_storage.gid,
                        )
                records.append(record)
                names.add((kind, name))
        order = {item: index for index, item in enumerate(expected)}
        records.sort(key=lambda record: order.get((record.kind, record.name), len(order)))
        return replace(state, resources=tuple(records))

    @staticmethod
    def _seeded_mounts_from_snapshot(
        state: RunState, policy: RuntimePolicySnapshot
    ) -> tuple[tuple[ResourceRecord, EphemeralMount], ...]:
        prefix = f"vdy-{state.lab_id}-{state.run_id[:12]}"
        volumes = {record.name: record for record in state.resources if record.kind == "volume"}
        try:
            return tuple(
                (volumes[f"{prefix}-volume-{mount.name}"], mount)
                for mount in policy.ephemeral_storage.seeded
            )
        except KeyError as exc:
            raise IntegrityError("rollback state lacks a reviewed seeded volume") from exc

    def _adopt_rollback_seeder(self, state: RunState, *, validate_policy: bool) -> RunState:
        """Adopt a transient prior-run seeder across every journal crash window."""
        policy = state.runtime_policy
        if policy is None:
            raise PolicyError("rollback state lacks its containment policy snapshot")
        prefix = f"vdy-{state.lab_id}-{state.run_id[:12]}"
        expected_name = f"{prefix}-seeder"
        ownership = Ownership.from_state(state)
        recorded = [
            record
            for record in state.resources
            if record.kind == "container" and record.name == expected_name
        ]
        if len(recorded) > 1:
            raise IntegrityError("rollback state contains duplicate transient seeders")
        matches: list[ResourceRecord] = []
        if recorded and self.docker.exists("container", recorded[0].object_id):
            matches.append(recorded[0])
        for object_id in self.docker.managed_resources(lab_id=state.lab_id)["container"]:
            if any(record.object_id == object_id for record in matches):
                continue
            if not self.docker.exists("container", object_id):
                continue
            inspection = self.docker.inspect("container", object_id)
            raw_name = inspection.get("Name")
            name = raw_name.removeprefix("/") if isinstance(raw_name, str) else ""
            if name == expected_name:
                matches.append(ResourceRecord("container", name, object_id))
        if len(matches) > 1:
            raise IntegrityError("multiple exact transient seeders match the rollback snapshot")
        resources = tuple(record for record in state.resources if record not in recorded)
        if not matches:
            return replace(state, resources=resources)
        seeder = matches[0]
        inspection = self.docker.validate_owned(seeder, ownership)
        if validate_policy:
            storage = policy.ephemeral_storage
            self.docker.validate_seeder_policy(
                inspection,
                image=state.requested_reference,
                seeded_mounts=self._seeded_mounts_from_snapshot(state, policy),
                uid=storage.uid,
                gid=storage.gid,
            )
        return replace(state, resources=(*resources, seeder))

    def _discard_rollback_seeder(self, state: RunState) -> tuple[RunState, bool]:
        prefix = f"vdy-{state.lab_id}-{state.run_id[:12]}"
        seeder_name = f"{prefix}-seeder"
        seeders = [
            record
            for record in state.resources
            if record.kind == "container" and record.name == seeder_name
        ]
        if len(seeders) > 1:
            raise IntegrityError("rollback state contains duplicate transient seeders")
        if not seeders:
            return state, False
        ownership = Ownership.from_state(state)
        applications = [
            record
            for record in state.resources
            if record.kind == "container" and record.name == f"{prefix}-app"
        ]
        if len(applications) == 1 and self.docker.exists(
            applications[0].kind, applications[0].object_id
        ):
            inspection = self.docker.validate_owned(applications[0], ownership)
            if self._running(inspection):
                self.docker.stop(applications[0])
        seeder = seeders[0]
        if self.docker.exists(seeder.kind, seeder.object_id):
            self.docker.validate_owned(seeder, ownership)
            self.docker.remove(seeder)
        return replace(
            state,
            resources=tuple(record for record in state.resources if record != seeder),
        ), True

    def _adopt_rollback_gateway(self, state: RunState, *, validate_policy: bool = True) -> RunState:
        """Recover an exact prior gateway created between rollback checkpoints."""
        if state.gateway_reference is None or state.upstream_port is None:
            raise PolicyError("prior runtime lacks a gateway rollback snapshot")
        ownership = Ownership.from_state(state)
        gateways = [
            record
            for record in state.resources
            if record.kind == "container" and record.name.endswith("-gateway")
        ]
        ingress_values = [
            record
            for record in state.resources
            if record.kind == "network" and record.name.endswith("-ingress")
        ]
        if len(gateways) != 1 or len(ingress_values) != 1:
            raise IntegrityError("prior runtime gateway rollback snapshot is malformed")
        old_gateway = gateways[0]
        if self.docker.exists(old_gateway.kind, old_gateway.object_id):
            inspection = self.docker.validate_owned(old_gateway, ownership)
            if validate_policy:
                self.docker.validate_gateway_policy(
                    inspection,
                    image=state.gateway_reference,
                    network=ingress_values[0].name,
                    upstream_port=state.upstream_port,
                    host_port=state.host_port,
                )
            return state

        matches: list[ResourceRecord] = []
        for object_id in self.docker.managed_resources(lab_id=state.lab_id)["container"]:
            inspection = self.docker.inspect("container", object_id)
            raw_name = inspection.get("Name")
            name = raw_name.removeprefix("/") if isinstance(raw_name, str) else ""
            if name != old_gateway.name:
                continue
            record = ResourceRecord("container", name, object_id)
            inspection = self.docker.validate_owned(record, ownership)
            if validate_policy:
                self.docker.validate_gateway_policy(
                    inspection,
                    image=state.gateway_reference,
                    network=ingress_values[0].name,
                    upstream_port=state.upstream_port,
                    host_port=state.host_port,
                )
            matches.append(record)
        if len(matches) > 1:
            raise IntegrityError("multiple exact prior gateways match the rollback snapshot")
        if not matches:
            return state
        return replace(
            state,
            resources=tuple(
                matches[0] if record == old_gateway else record for record in state.resources
            ),
        )

    def _restore_previous_update(self, lab: ReviewedLab, journal: UpdateJournal) -> RunState:
        candidate = self._adopt_journaled_candidate(lab, journal.candidate)
        previous = self._adopt_rollback_gateway(journal.previous)
        previous = self._adopt_rollback_seeder(previous, validate_policy=True)
        journal = replace(journal, candidate=candidate, previous=previous)
        self.store.save_update(journal)
        previous, discarded_seeder = self._discard_rollback_seeder(previous)
        if discarded_seeder:
            journal = replace(journal, previous=previous)
            self.store.save(previous)
            self.store.save_update(journal)
        if previous.gateway_reference is None or previous.upstream_port is None:
            raise PolicyError("prior runtime lacks a bounded gateway rollback snapshot")
        ownership = Ownership.from_state(previous)
        gateway_records = [
            record
            for record in previous.resources
            if record.kind == "container" and record.name.endswith("-gateway")
        ]
        if len(gateway_records) != 1:
            raise IntegrityError("prior runtime gateway snapshot is malformed")
        old_gateway = gateway_records[0]
        missing = [
            record
            for record in previous.resources
            if record != old_gateway and not self.docker.exists(record.kind, record.object_id)
        ]
        if missing:
            raise IntegrityError("prior runtime lost resources required for rollback")
        for record in previous.resources:
            if record != old_gateway:
                self.docker.validate_owned(record, ownership)
        if self.docker.exists(old_gateway.kind, old_gateway.object_id):
            self.docker.validate_owned(old_gateway, ownership)

        ingress = next(
            record
            for record in previous.resources
            if record.kind == "network" and record.name.endswith("-ingress")
        )
        internal = next(
            record
            for record in previous.resources
            if record.kind == "network" and record.name.endswith("-net")
        )
        if self.docker.exists(old_gateway.kind, old_gateway.object_id):
            self._ensure_network_connected(internal, old_gateway)

        # Validate the preserved side against its recorded policy before removing
        # the candidate. A cutover can legitimately have removed the old gateway,
        # so validate the exact surviving topology in that phase and validate the
        # complete topology again after recreating it.
        rollback_base = (
            previous
            if self.docker.exists(old_gateway.kind, old_gateway.object_id)
            else replace(
                previous,
                resources=tuple(record for record in previous.resources if record != old_gateway),
            )
        )
        self._validate_state(rollback_base, enforce_policy=True)

        # Both sides of the recovery boundary are now ownership-validated and the
        # surviving rollback base is policy-validated.
        self._cleanup(candidate, coexisting=(previous,))
        if self.docker.exists(old_gateway.kind, old_gateway.object_id):
            restored_gateway = old_gateway
        else:
            restored_gateway = self.docker.create_gateway(
                name=old_gateway.name,
                image=previous.gateway_reference,
                network=ingress.name,
                upstream_port=previous.upstream_port,
                host_port=previous.host_port,
                ownership=ownership,
            )
            previous = replace(
                previous,
                resources=tuple(
                    restored_gateway if record == old_gateway else record
                    for record in previous.resources
                ),
            )
            journal = replace(journal, previous=previous)
            self.store.save_update(journal)

        self._ensure_network_connected(internal, restored_gateway)

        inspections = self._validate_state(previous, enforce_policy=True)
        by_role = {
            self.docker._labels(record.kind, inspection).get(ROLE): (record, inspection)
            for record, inspection in zip(previous.resources, inspections, strict=True)
            if record.kind == "container"
        }
        application = by_role.get("application")
        gateway = by_role.get("gateway")
        if application is None or gateway is None:
            raise IntegrityError("rollback runtime lacks its application or gateway")
        for role, (record, inspection) in by_role.items():
            if role not in journal.running_roles and self._running(inspection):
                self.docker.stop(record)
        application_should_run = "application" in journal.running_roles
        gateway_should_run = "gateway" in journal.running_roles
        if application_should_run and not self._running(application[1]):

            def checkpoint_previous(current: RunState) -> None:
                nonlocal journal, previous
                previous = current
                journal = replace(journal, previous=current)
                self.store.save_update(journal)

            self._reseed_and_start(
                lab,
                previous,
                inspections,
                start_gateway=gateway_should_run,
                on_checkpoint=checkpoint_previous,
            )
        elif gateway_should_run and not self._running(gateway[1]):
            self.docker.start(gateway[0])
        final_inspections = self._validate_state(previous, enforce_policy=True)
        if not self._complete_layout(lab, previous, final_inspections):
            raise IntegrityError("rollback runtime failed its exact steady-state layout check")
        if application_should_run and gateway_should_run:
            policy = previous.runtime_policy
            if policy is None:  # pragma: no cover - journal parsing requires this snapshot
                raise IntegrityError("rollback runtime lost its health policy snapshot")
            self._health_snapshot(policy, previous.host_port)
        self.store.save(previous)
        self.store.delete_update(previous.lab_id)
        return previous

    def _recover_update(self, lab: ReviewedLab) -> None:
        journal = self.store.load_update(lab.manifest.id)
        if journal is None:
            return
        if journal.phase == "ready" and (
            journal.candidate.manifest_identity == lab.manifest_identity
        ):
            try:
                candidate = self._adopt_journaled_candidate(lab, journal.candidate)
                self._assert_no_orphans(lab.manifest.id, candidate, coexisting=(journal.previous,))
                status = self._status_from_state(lab, candidate)
                candidate_inspections = self._validate_state(candidate, lab=lab)
                actual_running_roles = {
                    self.docker._labels(record.kind, inspection).get(ROLE)
                    for record, inspection in zip(
                        candidate.resources, candidate_inspections, strict=True
                    )
                    if record.kind == "container" and self._running(inspection)
                }
                expected_running_roles = set(journal.running_roles)
                if not (
                    status.lock_match
                    and status.trusted_run
                    and actual_running_roles == expected_running_roles
                ):
                    raise PreflightError(
                        "ready update candidate no longer matches its preserved running state"
                    )
                if expected_running_roles == {"application", "gateway"}:
                    policy = candidate.runtime_policy
                    if policy is None:  # pragma: no cover - journal parsing requires it
                        raise IntegrityError("candidate lost its health policy snapshot")
                    self._health_snapshot(policy, candidate.host_port)
            except VulnDockyardError as candidate_error:
                try:
                    self._restore_previous_update(lab, journal)
                except VulnDockyardError as rollback_error:
                    raise PreflightError(
                        "ready update candidate failed validation or readiness and rollback "
                        f"also failed; update journal retained: {rollback_error}"
                    ) from candidate_error
                raise PreflightError(
                    "ready update candidate failed validation or readiness; "
                    "prior deployment restored"
                ) from candidate_error
            self.store.save(candidate)
            self._cleanup(journal.previous, coexisting=(candidate,))
            self.store.delete_update(lab.manifest.id)
            return
        self._restore_previous_update(lab, journal)

    def _recover_update_for_cleanup(self, lab: ReviewedLab) -> None:
        """Resolve an interrupted update without creating or starting anything."""
        journal = self.store.load_update(lab.manifest.id)
        if journal is None:
            return
        candidate = self._adopt_journaled_candidate(lab, journal.candidate)
        if journal.phase == "ready" and candidate.manifest_identity == lab.manifest_identity:
            self._assert_no_orphans(lab.manifest.id, candidate, coexisting=(journal.previous,))
            self.store.save(candidate)
            self._cleanup(journal.previous, coexisting=(candidate,))
            self.store.delete_update(lab.manifest.id)
            return

        previous = self._adopt_rollback_gateway(journal.previous, validate_policy=False)
        previous = self._adopt_rollback_seeder(previous, validate_policy=False)
        journal = replace(journal, previous=previous, candidate=candidate)
        self.store.save_update(journal)
        previous, discarded_seeder = self._discard_rollback_seeder(previous)
        if discarded_seeder:
            journal = replace(journal, previous=previous)
            self.store.save_update(journal)
        self._cleanup(candidate, coexisting=(previous,))
        ownership = Ownership.from_state(previous)
        surviving: list[ResourceRecord] = []
        for record in previous.resources:
            if not self.docker.exists(record.kind, record.object_id):
                continue
            self.docker.validate_owned(record, ownership)
            surviving.append(record)
        previous = replace(previous, resources=tuple(surviving))
        self.store.save(previous)
        self.store.delete_update(lab.manifest.id)

    def _refuse_pending_update_for_observation(self, lab: ReviewedLab) -> None:
        if self.store.load_update(lab.manifest.id) is not None:
            raise PolicyError(
                "an interrupted update is pending; status, logs, open, and verify never recover "
                "it because recovery may execute a lab. Use up, update, or restart for explicit "
                "execution recovery, or stop, remove, or purge for cleanup-only recovery"
            )
        state = self.store.load(lab.manifest.id)
        if state is not None and state.phase == "rebuild":
            raise PolicyError(
                "an interrupted persistent rebuild is pending; status, logs, open, and verify "
                "never execute recovery. Use up, restart, or rebuild to resume it, or stop, "
                "remove, reset, or purge for cleanup-only handling"
            )

    def _recover_runtime_transients_for_cleanup(self, lab: ReviewedLab) -> None:
        state = self.store.load(lab.manifest.id)
        # Schema v1/v2 state predates the complete policy snapshot needed to
        # recognize transient seeders.  It is deliberately ineligible for
        # execution/update recovery, but its exact recorded IDs and ownership
        # labels remain sufficient for stop/remove/purge cleanup.
        if state is None or state.runtime_policy is None:
            return
        adopted = self._adopt_journaled_candidate(lab, state)
        adopted = self._adopt_rollback_seeder(adopted, validate_policy=False)
        adopted, _ = self._discard_rollback_seeder(adopted)
        if adopted != state:
            self.store.save(adopted)

    def activate_reviewed_update(self, lab: ReviewedLab) -> RuntimeUpdate:
        """Activate only an installed reviewed candidate that differs from runtime state."""
        with self._lifecycle():
            self._validate_candidate(lab)
            self._preflight_lab(lab)
            current = self.store.load(lab.manifest.id)
            if current is not None and current.phase != "steady":
                raise PolicyError(
                    "an interrupted persistent rebuild must be resolved before an update"
                )
            self._recover_update(lab)
            previous = self.store.load(lab.manifest.id)
            if previous is None:
                status = self._status(lab)
                return RuntimeUpdate(
                    lab.manifest.id,
                    "no-runtime",
                    "",
                    lab.manifest_identity,
                    "",
                    "",
                    status,
                )
            if previous.manifest_identity == lab.manifest_identity:
                status = self._status(lab)
                return RuntimeUpdate(
                    lab.manifest.id,
                    "already-current",
                    previous.manifest_identity,
                    lab.manifest_identity,
                    previous.run_id,
                    previous.run_id,
                    status,
                )
            if lab.manifest.persistence_required or (
                previous.runtime_policy is not None and previous.runtime_policy.persistence_required
            ):
                raise PolicyError(
                    "transactional updates for persistent runtimes require a reviewed data "
                    "migration policy; no image was pulled and the current deployment is unchanged"
                )
            if not previous.trusted:
                raise PolicyError(
                    "an untrusted development runtime cannot be used as an update rollback base"
                )
            if (
                previous.gateway_reference is None
                or previous.upstream_port is None
                or previous.runtime_policy is None
            ):
                raise PolicyError(
                    "prior runtime predates the complete containment rollback snapshot; "
                    "it cannot be updated transactionally"
                )

            self._assert_no_orphans(lab.manifest.id, previous)
            previous_inspections = self._validate_state(previous, enforce_policy=True)
            if not self._complete_layout(lab, previous, previous_inspections):
                raise PolicyError("prior runtime is incomplete and cannot be a safe rollback base")
            running_roles = tuple(
                sorted(
                    self.docker._labels(record.kind, inspection)[ROLE]
                    for record, inspection in zip(
                        previous.resources, previous_inspections, strict=True
                    )
                    if record.kind == "container" and self._running(inspection)
                )
            )

            for image in lab.manifest.images:
                self.docker.pull(image.reference)
            temporary_port = self.temporary_port_selector(previous.host_port)
            if (
                not isinstance(temporary_port, int)
                or isinstance(temporary_port, bool)
                or not 1 <= temporary_port <= 65535
                or temporary_port == previous.host_port
            ):
                raise IntegrityError("temporary update port selector returned an unsafe port")

            candidate_run_id = uuid.uuid4().hex
            candidate_created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            candidate = RunState.create(
                lab_id=lab.manifest.id,
                run_id=candidate_run_id,
                manifest_identity=lab.manifest_identity,
                host_port=temporary_port,
                trusted=True,
                requested_reference=_application_image(lab).reference,
                resolved_digest=_application_image(lab).digest,
                resources=(),
                gateway_reference=_gateway_image(lab).reference,
                upstream_port=lab.manifest.services[0].internal_port,
                runtime_policy=_runtime_policy(lab),
                created_at=candidate_created_at,
            )
            journal = UpdateJournal(
                1,
                lab.manifest.id,
                "staged",
                previous,
                candidate,
                running_roles,
                temporary_port,
            )
            self.store.save_update(journal)

            def checkpoint(current: RunState) -> None:
                nonlocal journal
                journal = replace(journal, candidate=current)
                self.store.save_update(journal)

            try:
                candidate = self._create_run(
                    lab,
                    host_port=temporary_port,
                    selected_reference=_application_image(lab).reference,
                    trusted=True,
                    persist=False,
                    coexisting=(previous,),
                    run_id=candidate_run_id,
                    created_at=candidate_created_at,
                    on_checkpoint=checkpoint,
                )
                candidate_status = self._status_from_state(lab, candidate)
                if (
                    not candidate_status.lock_match
                    or not candidate_status.trusted_run
                    or candidate_status.state != "running"
                ):
                    raise IntegrityError(
                        "reviewed update candidate failed temporary-port identity verification"
                    )

                journal = replace(journal, phase="cutover", candidate=candidate)
                self.store.save_update(journal)
                candidate_inspections = self._validate_state(candidate, lab=lab)
                temporary_gateway = next(
                    record
                    for record, inspection in zip(
                        candidate.resources, candidate_inspections, strict=True
                    )
                    if record.kind == "container"
                    and self.docker._labels(record.kind, inspection).get(ROLE) == "gateway"
                )
                self.docker.remove(temporary_gateway)
                candidate = replace(
                    candidate,
                    host_port=previous.host_port,
                    resources=tuple(
                        record for record in candidate.resources if record != temporary_gateway
                    ),
                )
                journal = replace(journal, candidate=candidate)
                self.store.save_update(journal)

                old_gateway = next(
                    record
                    for record, inspection in zip(
                        previous.resources, previous_inspections, strict=True
                    )
                    if record.kind == "container"
                    and self.docker._labels(record.kind, inspection).get(ROLE) == "gateway"
                )
                self.docker.remove(old_gateway)

                ownership = Ownership.from_state(candidate)
                ingress = next(
                    record
                    for record in candidate.resources
                    if record.kind == "network" and record.name.endswith("-ingress")
                )
                internal = next(
                    record
                    for record in candidate.resources
                    if record.kind == "network" and record.name.endswith("-net")
                )
                final_gateway = self.docker.create_gateway(
                    name=temporary_gateway.name,
                    image=_gateway_image(lab).reference,
                    network=ingress.name,
                    upstream_port=lab.manifest.services[0].internal_port,
                    host_port=previous.host_port,
                    ownership=ownership,
                )
                candidate = replace(candidate, resources=(*candidate.resources, final_gateway))
                journal = replace(journal, candidate=candidate)
                self.store.save_update(journal)
                self._ensure_network_connected(internal, final_gateway)
                self.docker.start(final_gateway)
                self._health(lab, previous.host_port)

                final_status = self._status_from_state(lab, candidate)
                if (
                    not final_status.lock_match
                    or not final_status.trusted_run
                    or final_status.state != "running"
                ):
                    raise IntegrityError(
                        "reviewed update candidate failed final-port identity verification"
                    )
                final_inspections = self._validate_state(candidate, lab=lab)
                for record, inspection in zip(candidate.resources, final_inspections, strict=True):
                    if (
                        record.kind == "container"
                        and self.docker._labels(record.kind, inspection).get(ROLE)
                        not in running_roles
                        and self._running(inspection)
                    ):
                        self.docker.stop(record)
                journal = replace(journal, phase="ready", candidate=candidate)
                self.store.save_update(journal)
                self.store.save(candidate)
            except BaseException:
                pending = self.store.load_update(lab.manifest.id)
                if pending is not None:
                    self._restore_previous_update(lab, pending)
                raise

            # Candidate state is now authoritative. If cleanup is interrupted, the
            # ready journal lets the next lifecycle command safely finish by exact ID.
            self._cleanup(previous, coexisting=(candidate,))
            self.store.delete_update(lab.manifest.id)
            active = self._status(lab)
            return RuntimeUpdate(
                lab.manifest.id,
                "activated",
                previous.manifest_identity,
                lab.manifest_identity,
                previous.run_id,
                candidate.run_id,
                active,
            )

    def stop(self, lab: ReviewedLab) -> RuntimeStatus:
        with self._lifecycle():
            self._recover_update_for_cleanup(lab)
            self._recover_runtime_transients_for_cleanup(lab)
            return self._stop(lab)

    def _stop(self, lab: ReviewedLab) -> RuntimeStatus:
        state = self.store.load(lab.manifest.id)
        if state is None:
            self.docker.preflight()
            self._assert_no_orphans(lab.manifest.id)
            return self._status(lab)
        self._assert_no_orphans(lab.manifest.id, state)
        inspections = self._validate_state(state)
        for record, inspection in reversed(tuple(zip(state.resources, inspections, strict=True))):
            if record.kind == "container" and self._running(inspection):
                self.docker.stop(record)
        if state.phase == "rebuild":
            current_inspections = self._validate_state(state)
            resources = tuple(
                {
                    "kind": record.kind,
                    "name": record.name,
                    "id": record.object_id,
                    "role": self.docker._labels(record.kind, inspection).get(ROLE, "unknown"),
                    **(
                        {"state": "running" if self._running(inspection) else "stopped"}
                        if record.kind == "container"
                        else {}
                    ),
                }
                for record, inspection in zip(state.resources, current_inspections, strict=True)
            )
            return RuntimeStatus(
                lab.manifest.id,
                "degraded",
                self.url(lab, state.host_port),
                state.run_id,
                state.requested_reference,
                state.resolved_digest,
                lab.manifest.trust.value if state.trusted else "untrusted-development",
                state.trusted,
                False,
                resources,
            )
        return self._status(lab)

    def restart(self, lab: ReviewedLab) -> RuntimeStatus:
        with self._lifecycle():
            self._require_runnable(lab)
            self._preflight_lab(lab)
            self._recover_update(lab)
            current = self.store.load(lab.manifest.id)
            if current is not None and current.manifest_identity != lab.manifest_identity:
                raise PolicyError(
                    "installed reviewed lock differs from the preserved runtime; use update"
                )
            if current is not None and not current.trusted:
                raise PolicyError(
                    "restart refuses an untrusted development run before stopping it; "
                    "resume it explicitly with up --unsafe-development"
                )
            port = current.host_port if current else 80
            self._stop(lab)
            return self._up(lab, host_port=port)

    def _cleanup(self, state: RunState, *, coexisting: tuple[RunState, ...] = ()) -> None:
        self._assert_no_orphans(state.lab_id, state, coexisting=coexisting)
        ownership = Ownership.from_state(state)
        validated: list[ResourceRecord] = []
        for record in state.resources:
            if not self.docker.exists(record.kind, record.object_id):
                continue
            self.docker.validate_owned(record, ownership)
            validated.append(record)
        owned_container_ids = {
            record.object_id for record in validated if record.kind == "container"
        }
        for network in (record for record in validated if record.kind == "network"):
            foreign = self.docker.configured_network_consumers(network).difference(
                owned_container_ids
            )
            if foreign:
                raise PolicyError(
                    "managed network is configured on an unowned container; refusing cleanup"
                )
        for volume in (record for record in validated if record.kind == "volume"):
            foreign = self.docker.configured_volume_consumers(volume).difference(
                owned_container_ids
            )
            if foreign:
                raise PolicyError(
                    "managed volume is configured on an unowned container; refusing cleanup"
                )
        # Removal order is semantic and does not trust state-file ordering.
        for kind in ("container", "volume", "network"):
            for record in reversed(tuple(item for item in validated if item.kind == kind)):
                if not self.docker.exists(record.kind, record.object_id):
                    continue
                self.docker.validate_owned(record, ownership)
                if record.kind == "network" and self.docker.configured_network_consumers(record):
                    raise PolicyError(
                        "managed network still has configured container consumers; refusing cleanup"
                    )
                if record.kind == "volume" and self.docker.configured_volume_consumers(record):
                    raise PolicyError(
                        "managed volume still has configured container consumers; refusing cleanup"
                    )
                self.docker.remove(record)

    def _persistent_volume_records(
        self, state: RunState, policy: RuntimePolicySnapshot
    ) -> tuple[ResourceRecord, ...]:
        if not policy.persistence_required:
            raise PolicyError("persistent rebuild requires a persistent runtime snapshot")
        prefix = f"vdy-{state.lab_id}-{state.run_id[:12]}"
        expected_names = {
            f"{prefix}-volume-{mount.name}"
            for mount in policy.ephemeral_storage.seeded + policy.ephemeral_storage.empty
        }
        values = tuple(record for record in state.resources if record.kind == "volume")
        actual_names = {record.name for record in values}
        if len(values) != len(actual_names) or actual_names != expected_names:
            raise PolicyError("persistent runtime volume inventory is incomplete or ambiguous")
        return values

    def _validate_persistent_rebuild_resources(
        self, state: RunState, policy: RuntimePolicySnapshot
    ) -> tuple[ResourceRecord, ...]:
        self._assert_no_orphans(state.lab_id, state)
        ownership = Ownership.from_state(state)
        volumes = self._persistent_volume_records(state, policy)
        existing_containers = {
            record.object_id
            for record in state.resources
            if record.kind == "container" and self.docker.exists(record.kind, record.object_id)
        }
        for record in state.resources:
            if record.kind == "volume" and not self.docker.exists(record.kind, record.object_id):
                raise PolicyError(
                    "persistent runtime volume is missing; refusing to recreate or replace data"
                )
            if self.docker.exists(record.kind, record.object_id):
                self.docker.validate_owned(record, ownership)
        for volume in volumes:
            self.docker.validate_persistent_volume(volume, ownership)
            foreign = self.docker.configured_volume_consumers(volume).difference(
                existing_containers
            )
            if foreign:
                raise PolicyError(
                    "persistent volume is configured on an unowned container; refusing rebuild"
                )
        for network in (
            record
            for record in state.resources
            if record.kind == "network" and self.docker.exists(record.kind, record.object_id)
        ):
            foreign = self.docker.configured_network_consumers(network).difference(
                existing_containers
            )
            if foreign:
                raise PolicyError(
                    "managed network is configured on an unowned container; refusing rebuild"
                )
        return volumes

    def _resume_persistent_rebuild(self, lab: ReviewedLab, state: RunState) -> RuntimeStatus:
        policy = state.runtime_policy
        if state.phase != "rebuild" or policy is None or not policy.persistence_required:
            raise PolicyError("runtime does not contain a recoverable persistent rebuild")
        if state.manifest_identity != lab.manifest_identity or policy != _runtime_policy(lab):
            raise PolicyError("persistent rebuild state differs from the reviewed manifest")
        application_image = _application_image(lab)
        if (
            not state.trusted
            or state.requested_reference != application_image.reference
            or state.resolved_digest != application_image.digest
        ):
            raise PolicyError("persistent rebuild state differs from the reviewed image lock")

        for record in self._persistent_volume_records(state, policy):
            if not self.docker.exists(record.kind, record.object_id):
                raise PolicyError(
                    "persistent runtime volume is missing; refusing to recreate or replace data"
                )
        adopted = self._adopt_journaled_candidate(lab, state)
        if adopted != state:
            self.store.save(adopted)
            state = adopted
        volumes = self._validate_persistent_rebuild_resources(state, policy)
        ownership = Ownership.from_state(state)

        # Clear only transient resources from the already-journaled ownership epoch.
        # Every successful removal is atomically checkpointed; persistent volumes
        # remain present and recorded throughout the operation.
        for kind in ("container", "network"):
            for record in reversed(tuple(item for item in state.resources if item.kind == kind)):
                if self.docker.exists(record.kind, record.object_id):
                    self.docker.validate_owned(record, ownership)
                    if record.kind == "network" and self.docker.configured_network_consumers(
                        record
                    ):
                        raise PolicyError(
                            "managed network still has configured consumers during rebuild"
                        )
                    self.docker.remove(record)
                state = replace(
                    state,
                    resources=tuple(item for item in state.resources if item != record),
                )
                self.store.save(state)

        prefix = f"vdy-{state.lab_id}-{state.run_id[:12]}"
        storage = policy.ephemeral_storage
        mount_records = {record.name: record for record in volumes}
        volume_mounts = tuple(
            (mount_records[f"{prefix}-volume-{mount.name}"], mount)
            for mount in storage.seeded + storage.empty
        )

        def checkpoint(record: ResourceRecord) -> None:
            nonlocal state
            state = replace(state, resources=(*state.resources, record))
            self.store.save(state)

        try:
            network = self.docker.create_network(f"{prefix}-net", ownership, internal=True)
            checkpoint(network)
            ingress = self.docker.create_network(f"{prefix}-ingress", ownership, internal=False)
            checkpoint(ingress)
            application = self.docker.create_application(
                name=f"{prefix}-app",
                image=state.requested_reference,
                network=network.name,
                ownership=ownership,
                memory_mb=policy.memory_mb,
                cpus=policy.cpus,
                pids=policy.pids,
                read_only=policy.read_only_root,
                seeded_mounts=volume_mounts,
                empty_mounts=(),
                storage_uid=storage.uid,
                storage_gid=storage.gid,
            )
            checkpoint(application)
            if state.gateway_reference is None or state.upstream_port is None:
                raise PolicyError("persistent rebuild state lacks its gateway snapshot")
            gateway = self.docker.create_gateway(
                name=f"{prefix}-gateway",
                image=state.gateway_reference,
                network=ingress.name,
                upstream_port=state.upstream_port,
                host_port=state.host_port,
                ownership=ownership,
            )
            checkpoint(gateway)
            self._ensure_network_connected(network, gateway)
            if policy.outbound_required:
                self._ensure_network_connected(ingress, application)
            self.docker.start(application)
            if not self._running(self.docker.validate_owned(application, ownership)):
                raise PreflightError("application did not remain running after persistent rebuild")
            self.docker.start(gateway)
            self._health_snapshot(policy, state.host_port)
            steady = replace(state, phase="steady")
            inspections = self._validate_state(steady, lab=lab, enforce_policy=True)
            if not self._complete_layout(lab, steady, inspections):
                raise IntegrityError(
                    "persistent rebuild failed its exact steady-state layout check"
                )
            self.store.save(steady)
        except BaseException:
            # The phase remains recoverable. A later explicit execution command
            # adopts exact create/checkpoint-window resources before retrying.
            raise
        return self._status(lab)

    def remove(self, lab: ReviewedLab) -> RuntimeStatus:
        with self._lifecycle():
            self._recover_update_for_cleanup(lab)
            self._recover_runtime_transients_for_cleanup(lab)
            return self._remove(lab)

    def _remove(self, lab: ReviewedLab) -> RuntimeStatus:
        state = self.store.load(lab.manifest.id)
        if state is None:
            self.docker.preflight()
            self._assert_no_orphans(lab.manifest.id)
            return self._status(lab)
        self._cleanup(state)
        self.store.delete(lab.manifest.id)
        return self._status(lab)

    def rebuild(self, lab: ReviewedLab) -> RuntimeStatus:
        with self._lifecycle():
            self._require_runnable(lab)
            self._preflight_lab(lab)
            self._recover_update(lab)
            state = self.store.load(lab.manifest.id)
            if state is not None and state.manifest_identity != lab.manifest_identity:
                raise PolicyError(
                    "installed reviewed lock differs from the preserved runtime; use update"
                )
            if state is not None:
                application = _application_image(lab)
                if (
                    not state.trusted
                    or state.requested_reference != application.reference
                    or state.resolved_digest != application.digest
                ):
                    raise PolicyError(
                        "preserved runtime image reference differs from the reviewed lock; "
                        "remove and start it explicitly"
                    )
                if state.phase == "rebuild":
                    return self._resume_persistent_rebuild(lab, state)
                if state.runtime_policy is not None and state.runtime_policy.persistence_required:
                    self._validate_persistent_rebuild_resources(state, state.runtime_policy)
                    inspections = self._validate_state(state, lab=lab, enforce_policy=True)
                    if not self._complete_layout(lab, state, inspections):
                        raise PolicyError(
                            "persistent runtime is not complete enough to begin a rebuild"
                        )
                    rebuilding = replace(state, phase="rebuild")
                    self.store.save(rebuilding)
                    return self._resume_persistent_rebuild(lab, rebuilding)
            port = state.host_port if state else 80
            self._remove(lab)
            return self._up(lab, host_port=port)

    def reset(self, lab: ReviewedLab) -> RuntimeStatus:
        with self._lifecycle():
            self._require_runnable(lab)
            self._preflight_lab(lab)
            self._recover_update_for_cleanup(lab)
            self._recover_runtime_transients_for_cleanup(lab)
            state = self.store.load(lab.manifest.id)
            if state is not None and state.manifest_identity != lab.manifest_identity:
                raise PolicyError(
                    "installed reviewed lock differs from the preserved runtime; use update"
                )
            if state is not None:
                application = _application_image(lab)
                if (
                    not state.trusted
                    or state.requested_reference != application.reference
                    or state.resolved_digest != application.digest
                ):
                    raise PolicyError(
                        "reset refuses an untrusted or differently locked runtime; remove it "
                        "explicitly"
                    )
            port = state.host_port if state else 80
            self._remove(lab)
            return self._up(lab, host_port=port)

    def purge(self, lab: ReviewedLab, *, images: bool = False) -> RuntimeStatus:
        with self._lifecycle():
            self._recover_update_for_cleanup(lab)
            self._recover_runtime_transients_for_cleanup(lab)
            result = self._remove(lab)
            if images:
                for image in lab.lock.images:
                    self.docker.remove_image(image.reference)
            return result

    def logs(self, lab: ReviewedLab, *, follow: bool) -> str:
        with self._lifecycle():
            self._refuse_pending_update_for_observation(lab)
            return self._logs(lab, follow=follow)

    def _logs(self, lab: ReviewedLab, *, follow: bool) -> str:
        state = self.store.load(lab.manifest.id)
        if state is None:
            raise PolicyError(f"{lab.manifest.id} has no managed runtime")
        self._assert_no_orphans(lab.manifest.id, state)
        inspections = self._validate_state(state)
        applications = [
            record
            for record, inspection in zip(state.resources, inspections, strict=True)
            if record.kind == "container"
            and self.docker._labels(record.kind, inspection).get(ROLE) == "application"
        ]
        if len(applications) != 1:
            raise IntegrityError("managed runtime does not have exactly one application container")
        result = self.docker.logs(applications[0], follow=follow)
        return result.stdout + result.stderr

    def open(self, lab: ReviewedLab) -> str:
        status = self.status(lab)
        if status.state != "running":
            raise PolicyError(f"{lab.manifest.id} is not running")
        if not webbrowser.open(status.url):
            raise PreflightError(f"could not open a browser; visit {status.url}")
        return status.url

    def verify(self, lab: ReviewedLab) -> RuntimeStatus:
        with self._lifecycle():
            self._require_runnable(lab)
            self._refuse_pending_update_for_observation(lab)
            self._preflight_lab(lab)
            status = self._status(lab)
            if status.state != "running":
                raise PolicyError(f"{lab.manifest.id} is not running")
            state = self.store.load(lab.manifest.id)
            if state is None:  # pragma: no cover - held lifecycle lock prevents this
                raise IntegrityError("runtime state disappeared during verification")
            self._health(lab, state.host_port)
            if not status.lock_match:
                raise PolicyError("running application does not match the reviewed lock")
            return status

    def residual_audit(self) -> dict[str, tuple[str, ...]]:
        with self._lifecycle():
            self.docker.preflight()
            return self.docker.managed_resources()


def port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock.connect_ex(("127.0.0.1", port)) != 0

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
from .docker import ROLE, Docker, Ownership
from .errors import IntegrityError, PolicyError, PreflightError
from .models import DIGEST, OCI_NAME, AdapterStatus, Image
from .paths import Paths
from .state import ResourceRecord, RunState, StateStore, UpdateJournal


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
    return memory, float(cpus), pids, read_only


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
        self, state: RunState, *, current_identity: str | None = None
    ) -> tuple[dict[str, Any], ...]:
        if current_identity is not None and state.manifest_identity != current_identity:
            raise PolicyError(
                "existing state belongs to a different reviewed manifest; remove it explicitly"
            )
        ownership = Ownership.from_state(state)
        return tuple(self.docker.validate_owned(record, ownership) for record in state.resources)

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
        reviewed_timeout = lab.manifest.raw["health_check"]["timeout_seconds"]
        if not isinstance(reviewed_timeout, int) or isinstance(reviewed_timeout, bool):
            raise IntegrityError("manifest health-check timeout is malformed")
        health_timeout = min(self.docker.timeouts.health, float(reviewed_timeout))
        deadline = time.monotonic() + health_timeout
        for service in lab.manifest.services:
            identity = service.identity_regex
            if len(identity) > 160 or not identity.isprintable():
                raise IntegrityError("health identity marker is unsafe")
            last_error = "not attempted"
            request = urllib.request.Request(  # noqa: S310 - local http URL only
                self.local_url(port, service.health_path),
                headers={
                    "Host": lab.manifest.friendly_hostname,
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

    def _complete_layout(self, state: RunState, inspections: tuple[dict[str, Any], ...]) -> bool:
        kinds = [record.kind for record in state.resources]
        roles = {
            self.docker._labels(record.kind, inspection).get(ROLE)
            for record, inspection in zip(state.resources, inspections, strict=True)
            if record.kind == "container"
        }
        return (
            kinds.count("container") == 2
            and kinds.count("network") == 2
            and roles == {"application", "gateway"}
        )

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
            memory, cpus, pids, read_only = _resource_limits(lab)
            application = self.docker.create_application(
                name=f"{prefix}-app",
                image=selected_reference,
                network=network.name,
                ownership=ownership,
                memory_mb=memory,
                cpus=cpus,
                pids=pids,
                read_only=read_only,
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
            self.docker.connect_network(network, gateway_record)
            if lab.manifest.outbound_required:
                # Egress remains available only through the reviewed ingress network.
                self.docker.connect_network(ingress, application)
            self.docker.start(application)
            self.docker.start(gateway_record)
            self._health(lab, host_port)
        except BaseException:
            cleanup_state = snapshot()
            if cleanup_state.resources:
                if persist:
                    self.store.save(cleanup_state)
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
        self._assert_single_lab(lab.manifest.id, allow_multiple)
        existing = self.store.load(lab.manifest.id)
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
            inspections = (
                ()
                if missing
                else self._validate_state(existing, current_identity=lab.manifest_identity)
            )
            if missing or not self._complete_layout(existing, inspections):
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
            for record, inspection in container_pairs:
                if not self._running(inspection):
                    self.docker.start(record)
            try:
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
            self._recover_update(lab)
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
        return self._status_from_state(lab, state)

    def _status_from_state(self, lab: ReviewedLab, state: RunState) -> RuntimeStatus:
        inspections = self._validate_state(state)
        resource_status: list[dict[str, str]] = []
        running_values: list[bool] = []
        actual_images: dict[str, str] = {}
        for record, inspection in zip(state.resources, inspections, strict=True):
            item = {"kind": record.kind, "name": record.name, "id": record.object_id}
            if record.kind == "container":
                running = self._running(inspection)
                running_values.append(running)
                item["state"] = "running" if running else "stopped"
                labels = self.docker._labels(record.kind, inspection)
                role = labels.get(ROLE, "unknown")
                item["role"] = role
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
        if running_values and all(running_values):
            lifecycle = "running"
        elif any(running_values):
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

    def _adopt_journaled_candidate(self, state: RunState) -> RunState:
        """Adopt only exact intended names with every journaled ownership label."""
        ownership = Ownership.from_state(state)
        prefix = f"vdy-{state.lab_id}-{state.run_id[:12]}"
        expected = (
            ("network", f"{prefix}-net"),
            ("network", f"{prefix}-ingress"),
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
        for kind in ("network", "container"):
            for object_id in managed[kind]:
                if (kind, object_id) in recorded_ids:
                    continue
                inspection = self.docker.inspect(kind, object_id)
                raw_name = inspection.get("Name")
                name = raw_name.removeprefix("/") if isinstance(raw_name, str) else ""
                if (kind, name) not in expected_set or (kind, name) in names:
                    continue
                record = ResourceRecord(kind, name, object_id)
                self.docker.validate_owned(record, ownership)
                records.append(record)
                names.add((kind, name))
        order = {item: index for index, item in enumerate(expected)}
        records.sort(key=lambda record: order.get((record.kind, record.name), len(order)))
        return replace(state, resources=tuple(records))

    def _restore_previous_update(self, journal: UpdateJournal) -> RunState:
        candidate = self._adopt_journaled_candidate(journal.candidate)
        self.store.save_update(replace(journal, candidate=candidate))
        previous = journal.previous
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

        # Validate both sides of the recovery boundary before removing either.
        self._cleanup(candidate, coexisting=(previous,))

        if self.docker.exists(old_gateway.kind, old_gateway.object_id):
            restored_gateway = old_gateway
        else:
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
            restored_gateway = self.docker.create_gateway(
                name=old_gateway.name,
                image=previous.gateway_reference,
                network=ingress.name,
                upstream_port=previous.upstream_port,
                host_port=previous.host_port,
                ownership=ownership,
            )
            self.docker.connect_network(internal, restored_gateway)
            previous = replace(
                previous,
                resources=tuple(
                    restored_gateway if record == old_gateway else record
                    for record in previous.resources
                ),
            )

        inspections = self._validate_state(previous)
        for record, inspection in zip(previous.resources, inspections, strict=True):
            if record.kind != "container":
                continue
            role = self.docker._labels(record.kind, inspection).get(ROLE)
            should_run = role in journal.running_roles
            if should_run and not self._running(inspection):
                self.docker.start(record)
            elif not should_run and self._running(inspection):
                self.docker.stop(record)
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
            candidate = self._adopt_journaled_candidate(journal.candidate)
            self._assert_no_orphans(lab.manifest.id, candidate, coexisting=(journal.previous,))
            status = self._status_from_state(lab, candidate)
            if status.lock_match and status.trusted_run:
                self.store.save(candidate)
                self._cleanup(journal.previous, coexisting=(candidate,))
                self.store.delete_update(lab.manifest.id)
                return
        self._restore_previous_update(journal)

    def activate_reviewed_update(self, lab: ReviewedLab) -> RuntimeUpdate:
        """Activate only an installed reviewed candidate that differs from runtime state."""
        with self._lifecycle():
            self._recover_update(lab)
            self._validate_candidate(lab)
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
            if not previous.trusted:
                raise PolicyError(
                    "an untrusted development runtime cannot be used as an update rollback base"
                )
            if previous.gateway_reference is None or previous.upstream_port is None:
                raise PolicyError(
                    "prior runtime predates the bounded rollback snapshot; it cannot be updated "
                    "transactionally"
                )

            self._preflight_lab(lab)
            self._assert_no_orphans(lab.manifest.id, previous)
            previous_inspections = self._validate_state(previous)
            if not self._complete_layout(previous, previous_inspections):
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
                candidate_inspections = self._validate_state(candidate)
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
                self.docker.connect_network(internal, final_gateway)
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
                final_inspections = self._validate_state(candidate)
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
                    self._restore_previous_update(pending)
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
            self._recover_update(lab)
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
        return self._status(lab)

    def restart(self, lab: ReviewedLab) -> RuntimeStatus:
        with self._lifecycle():
            self._recover_update(lab)
            current = self.store.load(lab.manifest.id)
            if current is not None and current.manifest_identity != lab.manifest_identity:
                raise PolicyError(
                    "installed reviewed lock differs from the preserved runtime; use update"
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
        for record in reversed(validated):
            if not self.docker.exists(record.kind, record.object_id):
                continue
            self.docker.validate_owned(record, ownership)
            self.docker.remove(record)

    def remove(self, lab: ReviewedLab) -> RuntimeStatus:
        with self._lifecycle():
            self._recover_update(lab)
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
            port = state.host_port if state else 80
            self._remove(lab)
            return self._up(lab, host_port=port)

    def reset(self, lab: ReviewedLab) -> RuntimeStatus:
        # The operation differs from rebuild when adapters declare volumes; current
        # runnable v1 adapters are intentionally ephemeral and therefore converge.
        return self.rebuild(lab)

    def purge(self, lab: ReviewedLab, *, images: bool = False) -> RuntimeStatus:
        with self._lifecycle():
            self._recover_update(lab)
            result = self._remove(lab)
            if images:
                for image in lab.manifest.images:
                    self.docker.remove_image(image.reference)
            return result

    def logs(self, lab: ReviewedLab, *, follow: bool) -> str:
        with self._lifecycle():
            self._recover_update(lab)
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
            self._recover_update(lab)
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

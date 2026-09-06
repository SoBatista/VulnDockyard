"""Generic safe lab lifecycle."""

from __future__ import annotations

import contextlib
import re
import socket
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .catalogue import Catalogue, ReviewedLab
from .docker import ROLE, Docker, Ownership
from .errors import IntegrityError, PolicyError, PreflightError
from .models import AdapterStatus, Image
from .paths import Paths
from .state import ResourceRecord, RunState, StateStore


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
    ) -> None:
        self.catalogue = catalogue or Catalogue()
        self.paths = paths or Paths.discover()
        self.store = StateStore(self.paths)
        self.docker = docker or Docker()
        self.sleeper = sleeper

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

    def pull(self, lab: ReviewedLab) -> tuple[str, ...]:
        self._require_runnable(lab)
        self.docker.preflight()
        references = tuple(image.reference for image in lab.manifest.images)
        for reference in references:
            self.docker.pull(reference)
        return references

    def _assert_single_lab(self, lab_id: str, allow_multiple: bool) -> None:
        if allow_multiple:
            return
        others = [state.lab_id for state in self.store.all() if state.lab_id != lab_id]
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

    def _health(self, lab: ReviewedLab, port: int) -> None:
        deadline = time.monotonic() + self.docker.timeouts.health
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
                    with urllib.request.urlopen(  # noqa: S310 - fixed to 127.0.0.1
                        request, timeout=min(3.0, self.docker.timeouts.health)
                    ) as response:
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
        self._require_runnable(lab)
        if not 1 <= host_port <= 65535:
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
            if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", unsafe_image):
                raise PolicyError(
                    "unsafe development images must still use an immutable sha256 digest"
                )
        self.paths.ensure()
        self._assert_single_lab(lab.manifest.id, allow_multiple)
        self.docker.preflight()
        existing = self.store.load(lab.manifest.id)
        if existing is not None:
            inspections = self._validate_state(existing, current_identity=lab.manifest_identity)
            container_pairs = [
                (record, inspection)
                for record, inspection in zip(existing.resources, inspections, strict=True)
                if record.kind == "container"
            ]
            if all(self._running(inspection) for _, inspection in container_pairs):
                return self.status(lab)
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
            return self.status(lab)

        app = _application_image(lab)
        gateway = _gateway_image(lab)
        selected_reference = unsafe_image or app.reference
        trusted = unsafe_image is None
        # Pull every reviewed support image; an unsafe app never lends its run reviewed trust.
        self.docker.pull(selected_reference)
        self.docker.pull(gateway.reference)
        run_id = uuid.uuid4().hex
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ownership = Ownership(lab.manifest.id, lab.manifest_identity, run_id, created_at, trusted)
        prefix = f"vdy-{lab.manifest.id}-{run_id[:12]}"
        resources: list[ResourceRecord] = []
        state: RunState | None = None

        def checkpoint() -> RunState:
            current = RunState.create(
                lab_id=lab.manifest.id,
                run_id=run_id,
                manifest_identity=lab.manifest_identity,
                host_port=host_port,
                trusted=trusted,
                requested_reference=selected_reference,
                resolved_digest=selected_reference.rsplit("@", 1)[-1],
                resources=tuple(resources),
                created_at=created_at,
            )
            self.store.save(current)
            return current

        try:
            network = self.docker.create_network(f"{prefix}-net", ownership, internal=True)
            resources.append(network)
            state = checkpoint()
            ingress = self.docker.create_network(f"{prefix}-ingress", ownership, internal=False)
            resources.append(ingress)
            state = checkpoint()
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
            state = checkpoint()
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
            self.docker.start(application)
            self.docker.start(gateway_record)
            self._health(lab, host_port)
        except BaseException:
            cleanup_state = state or RunState.create(
                lab_id=lab.manifest.id,
                run_id=run_id,
                manifest_identity=lab.manifest_identity,
                host_port=host_port,
                trusted=trusted,
                requested_reference=selected_reference,
                resolved_digest=selected_reference.rsplit("@", 1)[-1],
                resources=tuple(resources),
                created_at=created_at,
            )
            if cleanup_state.resources:
                self.store.save(cleanup_state)
                try:
                    self._cleanup(cleanup_state)
                except Exception:
                    # Exact state remains for a bounded explicit recovery attempt.
                    raise
                else:
                    self.store.delete(lab.manifest.id)
            raise
        return self.status(lab)

    def status(self, lab: ReviewedLab) -> RuntimeStatus:
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
        inspections = self._validate_state(state)
        resource_status: list[dict[str, str]] = []
        running_values: list[bool] = []
        for record, inspection in zip(state.resources, inspections, strict=True):
            item = {"kind": record.kind, "name": record.name, "id": record.object_id}
            if record.kind == "container":
                running = self._running(inspection)
                running_values.append(running)
                item["state"] = "running" if running else "stopped"
                labels = self.docker._labels(record.kind, inspection)
                item["role"] = labels.get(ROLE, "unknown")
            resource_status.append(item)
        lifecycle = "running" if running_values and all(running_values) else "stopped"
        locked = {image.digest for image in lab.lock.images if image.role == "application"}
        return RuntimeStatus(
            lab.manifest.id,
            lifecycle,
            self.url(lab, state.host_port),
            state.run_id,
            state.requested_reference,
            state.resolved_digest,
            lab.manifest.trust.value,
            state.trusted,
            state.trusted
            and state.manifest_identity == lab.manifest_identity
            and state.resolved_digest in locked,
            tuple(resource_status),
        )

    def stop(self, lab: ReviewedLab) -> RuntimeStatus:
        state = self.store.load(lab.manifest.id)
        if state is None:
            return self.status(lab)
        inspections = self._validate_state(state)
        for record, inspection in reversed(tuple(zip(state.resources, inspections, strict=True))):
            if record.kind == "container" and self._running(inspection):
                self.docker.stop(record)
        return self.status(lab)

    def restart(self, lab: ReviewedLab) -> RuntimeStatus:
        current = self.store.load(lab.manifest.id)
        port = current.host_port if current else 80
        self.stop(lab)
        return self.up(lab, host_port=port)

    def _cleanup(self, state: RunState) -> None:
        ownership = Ownership.from_state(state)
        for record in reversed(state.resources):
            if not self.docker.exists(record.kind, record.object_id):
                continue
            self.docker.validate_owned(record, ownership)
            self.docker.remove(record)

    def remove(self, lab: ReviewedLab) -> RuntimeStatus:
        state = self.store.load(lab.manifest.id)
        if state is None:
            return self.status(lab)
        self._cleanup(state)
        self.store.delete(lab.manifest.id)
        return self.status(lab)

    def rebuild(self, lab: ReviewedLab) -> RuntimeStatus:
        state = self.store.load(lab.manifest.id)
        port = state.host_port if state else 80
        self.remove(lab)
        return self.up(lab, host_port=port)

    def reset(self, lab: ReviewedLab) -> RuntimeStatus:
        # The operation differs from rebuild when adapters declare volumes; current
        # runnable v1 adapters are intentionally ephemeral and therefore converge.
        return self.rebuild(lab)

    def purge(self, lab: ReviewedLab, *, images: bool = False) -> RuntimeStatus:
        result = self.remove(lab)
        if images:
            for image in lab.manifest.images:
                self.docker.remove_image(image.reference)
        return result

    def logs(self, lab: ReviewedLab, *, follow: bool) -> str:
        state = self.store.load(lab.manifest.id)
        if state is None:
            raise PolicyError(f"{lab.manifest.id} has no managed runtime")
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
        status = self.status(lab)
        if status.state != "running":
            raise PolicyError(f"{lab.manifest.id} is not running")
        self._health(lab, self.store.load(lab.manifest.id).host_port)  # type: ignore[union-attr]
        if not status.lock_match:
            raise PolicyError("running application does not match the reviewed lock")
        return status

    def residual_audit(self) -> dict[str, tuple[str, ...]]:
        self.docker.preflight()
        return self.docker.managed_resources()


def port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock.connect_ex(("127.0.0.1", port)) != 0

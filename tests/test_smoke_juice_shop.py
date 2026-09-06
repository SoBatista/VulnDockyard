from __future__ import annotations

import os

import pytest

from vulndockyard.catalogue import Catalogue
from vulndockyard.docker import ROLE, Docker
from vulndockyard.paths import Paths
from vulndockyard.runtime import Runtime, port_available

pytestmark = [
    pytest.mark.docker,
    pytest.mark.smoke,
    pytest.mark.skipif(
        os.environ.get("VDY_RUN_DOCKER_TESTS") != "1",
        reason="explicit Docker release-gate opt-in is required",
    ),
]


def test_juice_shop_complete_behavioral_equivalence(xdg_paths: Paths) -> None:
    port = int(os.environ.get("VDY_SMOKE_PORT", "18089"))
    assert port_available(port), f"required explicit smoke port is busy: {port}"
    lab = Catalogue().get("juice-shop")
    docker = Docker()
    runtime = Runtime(paths=xdg_paths, docker=docker)
    assert all(not values for values in runtime.residual_audit().values())
    try:
        started = runtime.up(lab, host_port=port)
        assert started.state == "running"
        assert started.trusted_run and started.lock_match
        assert started.requested_reference.endswith("@" + started.resolved_digest)
        assert started.trust_level == "upstream-pinned"
        original_run = started.run_id

        state = runtime.store.load(lab.manifest.id)
        assert state is not None
        inspections = runtime._validate_state(state, current_identity=lab.manifest_identity)
        resources = tuple(zip(state.resources, inspections, strict=True))
        app_record, app = next(
            (record, inspection)
            for record, inspection in resources
            if record.kind == "container"
            and docker._labels(record.kind, inspection)[ROLE] == "application"
        )
        _, gateway = next(
            (record, inspection)
            for record, inspection in resources
            if record.kind == "container"
            and docker._labels(record.kind, inspection)[ROLE] == "gateway"
        )
        assert app["HostConfig"]["PortBindings"] == {}
        assert app["HostConfig"]["RestartPolicy"]["Name"] == "no"
        assert "ALL" in app["HostConfig"]["CapDrop"]
        assert gateway["HostConfig"]["PortBindings"]["8080/tcp"] == [
            {"HostIp": "127.0.0.1", "HostPort": str(port)}
        ]
        assert gateway["HostConfig"]["RestartPolicy"]["Name"] == "no"
        assert "NET_BIND_SERVICE" in gateway["HostConfig"]["CapAdd"]
        network = next(record for record in state.resources if record.name.endswith("-net"))
        assert docker.inspect("network", network.object_id)["Internal"] is True

        repeated = runtime.up(lab, host_port=port)
        assert repeated.run_id == original_run
        assert runtime.verify(lab).lock_match
        assert runtime.stop(lab).state == "stopped"
        assert runtime.stop(lab).state == "stopped"
        assert runtime.up(lab).run_id == original_run

        rebuilt = runtime.rebuild(lab)
        assert rebuilt.run_id != original_run
        assert rebuilt.requested_reference == started.requested_reference
        reset = runtime.reset(lab)
        assert reset.run_id != rebuilt.run_id
        assert runtime.verify(lab).lock_match
        assert runtime.remove(lab).state == "absent"
        assert runtime.remove(lab).state == "absent"
    finally:
        # This cleanup remains ownership-validated and bounded.
        runtime.remove(lab)
    assert runtime.store.load(lab.manifest.id) is None
    assert all(not values for values in runtime.residual_audit().values())

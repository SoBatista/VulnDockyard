from __future__ import annotations

import http.client
import json
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


def _request(
    port: int, path: str, *, method: str = "GET", payload: dict[str, object] | None = None
) -> tuple[int, bytes]:
    body = None if payload is None else json.dumps(payload).encode()
    headers = {"Host": "juice-shop.test", "User-Agent": "VulnDockyard-smoke/1"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        content = response.read(1_048_577)
        assert len(content) <= 1_048_576
        return response.status, content
    finally:
        connection.close()


def _assert_training_functionality(port: int) -> None:
    root_status, root = _request(port, "/")
    assert root_status == 200 and b"OWASP Juice Shop" in root
    challenge_status, challenge_body = _request(port, "/api/Challenges")
    assert challenge_status == 200
    challenges = json.loads(challenge_body)["data"]
    assert isinstance(challenges, list) and len(challenges) >= 50
    names = {item["name"] for item in challenges}
    assert {"Score Board", "Login Admin"}.issubset(names)
    question_status, questions_body = _request(port, "/api/SecurityQuestions")
    assert question_status == 200
    assert len(json.loads(questions_body)["data"]) >= 1
    for route in ("/score-board", "/tutorial", "/coding-challenge"):
        status, body = _request(port, route)
        assert status == 200 and b"OWASP Juice Shop" in body


def _register_and_login(port: int, email: str) -> None:
    status, _ = _request(
        port,
        "/api/Users",
        method="POST",
        payload={"email": email, "password": "Vdy-Smoke-1!", "passwordRepeat": "Vdy-Smoke-1!"},
    )
    assert status == 201
    status, body = _request(
        port,
        "/rest/user/login",
        method="POST",
        payload={"email": email, "password": "Vdy-Smoke-1!"},
    )
    assert status == 200 and b"authentication" in body


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
        _assert_training_functionality(port)

        state = runtime.store.load(lab.manifest.id)
        assert state is not None
        inspections = runtime._validate_state(state, current_identity=lab.manifest_identity)
        resources = tuple(zip(state.resources, inspections, strict=True))
        _app_record, app = next(
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
        assert {capability.removeprefix("CAP_") for capability in app["HostConfig"]["CapDrop"]} == {
            "ALL"
        }
        assert gateway["HostConfig"]["PortBindings"]["8080/tcp"] == [
            {"HostIp": "127.0.0.1", "HostPort": str(port)}
        ]
        assert gateway["HostConfig"]["RestartPolicy"]["Name"] == "no"
        assert gateway["Config"]["User"] == "1000:1000"
        assert {
            capability.removeprefix("CAP_") for capability in gateway["HostConfig"]["CapAdd"]
        } == {"NET_BIND_SERVICE"}
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
        account = f"vdy-smoke-{rebuilt.run_id[:12]}@example.test"
        _register_and_login(port, account)
        reset = runtime.reset(lab)
        assert reset.run_id != rebuilt.run_id
        assert runtime.verify(lab).lock_match
        _assert_training_functionality(port)
        login_status, _ = _request(
            port,
            "/rest/user/login",
            method="POST",
            payload={"email": account, "password": "Vdy-Smoke-1!"},
        )
        assert login_status in {401, 403}
        assert runtime.remove(lab).state == "absent"
        assert runtime.remove(lab).state == "absent"
    finally:
        # This cleanup remains ownership-validated and bounded.
        runtime.remove(lab)
    assert runtime.store.load(lab.manifest.id) is None
    assert all(not values for values in runtime.residual_audit().values())

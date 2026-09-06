from __future__ import annotations

import dataclasses
import http.client
import json
import os
from pathlib import Path

import pytest

from vulndockyard.catalogue import Catalogue, ReviewedLab, identity, template_identity
from vulndockyard.docker import GATEWAY_MODE_IPV4, ROLE, Docker
from vulndockyard.errors import PreflightError
from vulndockyard.models import Manifest
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


def _reviewed_prior(candidate: ReviewedLab, root: Path) -> ReviewedLab:
    manifest = json.loads(json.dumps(candidate.manifest.raw))
    manifest["description"] += " Test-only prior reviewed metadata revision."
    manifest_root = root / "manifests"
    lock_root = root / "locks"
    manifest_root.mkdir(mode=0o700, parents=True)
    lock_root.mkdir(mode=0o700)
    (manifest_root / "juice-shop.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (lock_root / "juice-shop.lock.json").write_text(
        json.dumps(candidate.lock.raw, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    prior = Catalogue(root=root).get("juice-shop")
    assert prior.manifest_identity == identity(prior.manifest.raw)
    assert prior.manifest_identity != candidate.manifest_identity
    assert prior.manifest.images == candidate.manifest.images
    assert prior.lock.images == candidate.lock.images
    assert template_identity(prior.manifest) == template_identity(candidate.manifest)
    assert prior.lock.template_sha256 == candidate.lock.template_sha256
    return prior


def _persistent_review(candidate: ReviewedLab) -> ReviewedLab:
    raw = json.loads(json.dumps(candidate.manifest.raw))
    raw["persistence"]["required"] = True
    manifest = Manifest.parse(raw)
    lock = dataclasses.replace(candidate.lock, template_sha256=template_identity(manifest))
    return ReviewedLab(manifest, lock, identity(raw))


def test_juice_shop_complete_behavioral_equivalence(
    xdg_paths: Paths, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    port = int(os.environ.get("VDY_SMOKE_PORT", "18089"))
    update_port = int(os.environ.get("VDY_SMOKE_UPDATE_PORT", "18090"))
    assert port_available(port), f"required explicit smoke port is busy: {port}"
    assert update_port != port
    assert port_available(update_port), f"required update smoke port is busy: {update_port}"
    lab = Catalogue().get("juice-shop")
    previous_lab = _reviewed_prior(lab, tmp_path / "prior-catalogue")
    docker = Docker()
    runtime = Runtime(
        paths=xdg_paths,
        docker=docker,
        temporary_port_selector=lambda excluded: update_port,
    )
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
        expected_logs = {
            "Type": "local",
            "Config": {"compress": "true", "max-file": "2", "max-size": "10m"},
        }
        assert app["HostConfig"]["LogConfig"] == expected_logs
        assert {capability.removeprefix("CAP_") for capability in app["HostConfig"]["CapDrop"]} == {
            "ALL"
        }
        assert gateway["HostConfig"]["PortBindings"]["8080/tcp"] == [
            {"HostIp": "127.0.0.1", "HostPort": str(port)}
        ]
        assert gateway["HostConfig"]["RestartPolicy"]["Name"] == "no"
        assert gateway["HostConfig"]["LogConfig"] == expected_logs
        assert gateway["Config"]["User"] == "1000:1000"
        assert {
            capability.removeprefix("CAP_") for capability in gateway["HostConfig"]["CapAdd"]
        } == {"NET_BIND_SERVICE"}
        network = next(record for record in state.resources if record.name.endswith("-net"))
        internal_network = docker.inspect("network", network.object_id)
        assert internal_network["Internal"] is True
        assert internal_network["Options"][GATEWAY_MODE_IPV4] == "isolated"
        ingress = next(record for record in state.resources if record.name.endswith("-ingress"))
        ingress_network = docker.inspect("network", ingress.object_id)
        assert ingress_network["Internal"] is False
        assert ingress_network["Options"][GATEWAY_MODE_IPV4] == "nat"

        repeated = runtime.up(lab, host_port=port)
        assert repeated.run_id == original_run
        assert runtime.verify(lab).lock_match
        assert isinstance(runtime.logs(lab, follow=False), str)
        restarted = runtime.restart(lab)
        assert restarted.run_id == original_run
        _assert_training_functionality(port)
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

        rollback_base = runtime.up(previous_lab, host_port=port)
        rollback_state = runtime.store.load(lab.manifest.id)
        assert rollback_state is not None
        previous_gateway = next(
            record for record in rollback_state.resources if record.name.endswith("-gateway")
        )
        stable_resources = {
            record.object_id
            for record in rollback_state.resources
            if not record.name.endswith("-gateway")
        }
        checked_ports: list[int] = []
        candidate_ids: set[tuple[str, str]] = set()
        real_health = runtime._health

        def fail_final_candidate(selected: ReviewedLab, checked_port: int) -> None:
            checked_ports.append(checked_port)
            if checked_port == port:
                journal = runtime.store.load_update(lab.manifest.id)
                assert journal is not None and journal.phase == "cutover"
                candidate_ids.update(
                    (record.kind, record.object_id) for record in journal.candidate.resources
                )
                raise PreflightError("injected final-port candidate identity failure")
            real_health(selected, checked_port)

        monkeypatch.setattr(runtime, "_health", fail_final_candidate)
        with pytest.raises(PreflightError, match="injected final-port"):
            runtime.activate_reviewed_update(lab)
        monkeypatch.setattr(runtime, "_health", real_health)
        assert checked_ports == [update_port, port]
        restored = runtime.store.load(lab.manifest.id)
        assert restored is not None
        assert restored.run_id == rollback_base.run_id
        assert restored.manifest_identity == previous_lab.manifest_identity
        assert stable_resources.issubset({record.object_id for record in restored.resources})
        restored_gateway = next(
            record for record in restored.resources if record.name.endswith("-gateway")
        )
        assert restored_gateway.object_id != previous_gateway.object_id
        assert candidate_ids
        assert all(not docker.exists(kind, object_id) for kind, object_id in candidate_ids)
        assert runtime.store.load_update(lab.manifest.id) is None
        assert runtime.verify(previous_lab).lock_match
        _assert_training_functionality(port)
        assert port_available(update_port)

        restored_resources = tuple(restored.resources)
        activated = runtime.activate_reviewed_update(lab)
        assert activated.outcome == "activated"
        assert activated.previous_manifest_identity == previous_lab.manifest_identity
        assert activated.candidate_manifest_identity == lab.manifest_identity
        assert activated.previous_run_id == rollback_base.run_id
        assert activated.active_run_id != rollback_base.run_id
        assert all(
            not docker.exists(record.kind, record.object_id) for record in restored_resources
        )
        assert runtime.verify(lab).lock_match
        _assert_training_functionality(port)
        assert port_available(update_port)
        assert runtime.remove(lab).state == "absent"
    finally:
        # This cleanup remains ownership-validated and bounded.
        runtime.remove(lab)
    assert runtime.store.load(lab.manifest.id) is None
    assert runtime.store.load_update(lab.manifest.id) is None
    assert port_available(port)
    assert port_available(update_port)
    assert all(not values for values in runtime.residual_audit().values())


def test_juice_shop_persistent_storage_runs_nonroot_and_resets_exact_data(
    xdg_paths: Paths,
) -> None:
    port = int(os.environ.get("VDY_PERSISTENT_SMOKE_PORT", "18091"))
    assert port_available(port), f"required explicit persistent smoke port is busy: {port}"
    lab = _persistent_review(Catalogue().get("juice-shop"))
    docker = Docker()
    runtime = Runtime(paths=xdg_paths, docker=docker)
    assert all(not values for values in runtime.residual_audit().values())
    try:
        started = runtime.up(lab, host_port=port)
        assert started.state == "running"
        assert started.trusted_run and started.lock_match
        state = runtime.store.load(lab.manifest.id)
        assert state is not None and state.phase == "steady"
        assert state.runtime_policy is not None and state.runtime_policy.persistence_required
        inspections = runtime._validate_state(state, lab=lab, enforce_policy=True)
        resources = tuple(zip(state.resources, inspections, strict=True))
        application = next(
            inspection
            for record, inspection in resources
            if record.kind == "container"
            and docker._labels(record.kind, inspection)[ROLE] == "application"
        )
        assert application["Config"]["User"] == "65532:65532"
        assert not any(
            record.kind == "container" and docker._labels(record.kind, inspection)[ROLE] == "seeder"
            for record, inspection in resources
        )
        original_volumes = tuple(record for record in state.resources if record.kind == "volume")
        assert len(original_volumes) == len(
            lab.manifest.ephemeral_storage.seeded + lab.manifest.ephemeral_storage.empty
        )

        account = f"vdy-persistent-{started.run_id[:12]}@example.test"
        _register_and_login(port, account)
        rebuilt = runtime.rebuild(lab)
        assert rebuilt.run_id == started.run_id
        rebuilt_state = runtime.store.load(lab.manifest.id)
        assert rebuilt_state is not None and rebuilt_state.phase == "steady"
        assert tuple(
            record.object_id for record in rebuilt_state.resources if record.kind == "volume"
        ) == tuple(record.object_id for record in original_volumes)
        _register_and_login(port, f"second-{account}")
        login_status, login_body = _request(
            port,
            "/rest/user/login",
            method="POST",
            payload={"email": account, "password": "Vdy-Smoke-1!"},
        )
        assert login_status == 200 and b"authentication" in login_body

        reset = runtime.reset(lab)
        assert reset.run_id != rebuilt.run_id
        assert all(not docker.exists(record.kind, record.object_id) for record in original_volumes)
        login_status, _ = _request(
            port,
            "/rest/user/login",
            method="POST",
            payload={"email": account, "password": "Vdy-Smoke-1!"},
        )
        assert login_status in {401, 403}
        _assert_training_functionality(port)
    finally:
        runtime.remove(lab)
    assert runtime.store.load(lab.manifest.id) is None
    assert port_available(port)
    assert all(not values for values in runtime.residual_audit().values())

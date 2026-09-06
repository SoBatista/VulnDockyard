from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

import pytest

from vulndockyard.docker import (
    CREATED,
    LAB,
    MANIFEST,
    MANIFEST_VERSION,
    OWNER,
    RUN,
    TRUSTED,
    Docker,
    Ownership,
    Timeouts,
)
from vulndockyard.errors import IntegrityError, PolicyError
from vulndockyard.process import Result, Runner
from vulndockyard.state import ResourceRecord


class RecordingRunner(Runner):
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.responses: list[Result] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> Result:
        call = tuple(argv)
        self.calls.append(call)
        if self.responses:
            return self.responses.pop(0)
        return Result(call, 0, "a" * 64 + "\n", "")


def ownership() -> Ownership:
    return Ownership("juice-shop", "b" * 64, "c" * 32, "2026-09-06T00:00:00Z", True)


def labels(value: Ownership) -> dict[str, str]:
    items = iter(value.labels("application"))
    result: dict[str, str] = {}
    for marker, assignment in zip(items, items, strict=True):
        assert marker == "--label"
        key, item = assignment.split("=", 1)
        result[key] = item
    return result


def test_application_command_has_containment_and_no_publication() -> None:
    runner = RecordingRunner()
    docker = Docker(runner, Timeouts())
    record = docker.create_application(
        name="vdy-juice-app",
        image="example/app@sha256:" + "1" * 64,
        network="vdy-network",
        ownership=ownership(),
        memory_mb=512,
        cpus=0.5,
        pids=256,
        read_only=False,
    )
    call = runner.calls[-1]
    assert record.object_id == "a" * 64
    assert call[:3] == ("docker", "container", "create")
    assert "--publish" not in call
    assert (call[call.index("--restart")], call[call.index("--restart") + 1]) == ("--restart", "no")
    assert call[call.index("--cap-drop") + 1] == "ALL"
    assert call[call.index("--security-opt") + 1] == "no-new-privileges=true"
    assert "--privileged" not in call


def test_gateway_command_binds_only_loopback_and_fixed_target() -> None:
    runner = RecordingRunner()
    docker = Docker(runner)
    docker.create_gateway(
        name="vdy-gateway",
        image="docker.io/library/caddy@sha256:" + "2" * 64,
        network="vdy-ingress",
        upstream_port=3000,
        host_port=8080,
        ownership=ownership(),
    )
    call = runner.calls[-1]
    assert call[call.index("--publish") + 1] == "127.0.0.1:8080:8080"
    assert call[call.index("--cap-add") + 1] == "NET_BIND_SERVICE"
    assert call[-6:] == ("caddy", "reverse-proxy", "--from", ":8080", "--to", "app:3000")


def test_network_and_cleanup_commands_are_scoped() -> None:
    runner = RecordingRunner()
    docker = Docker(runner)
    network = docker.create_network("vdy-net", ownership(), internal=True)
    assert "--internal" in runner.calls[-1]
    docker.remove(ResourceRecord("container", "app", "d" * 64))
    assert runner.calls[-1] == ("docker", "container", "rm", "--force", "d" * 64)
    docker.remove(network)
    assert runner.calls[-1] == ("docker", "network", "rm", "a" * 64)
    assert all("prune" not in call for argv in runner.calls for call in argv)


def test_pull_requires_digest_and_verifies_repository_identity() -> None:
    runner = RecordingRunner()
    docker = Docker(runner)
    with pytest.raises(PolicyError, match="immutable"):
        docker.pull("example/app:latest")
    reference = "docker.io/library/caddy@sha256:" + "e" * 64
    inspection = [{"RepoDigests": ["caddy@sha256:" + "e" * 64]}]
    runner.responses = [
        Result(("docker",), 0, "", ""),
        Result(("docker",), 0, json.dumps(inspection), ""),
    ]
    docker.pull(reference)
    runner.responses = [
        Result(("docker",), 0, "", ""),
        Result(("docker",), 0, json.dumps([{"RepoDigests": ["other@sha256:" + "e" * 64]}]), ""),
    ]
    with pytest.raises(IntegrityError, match="does not report"):
        docker.pull(reference)


def test_ownership_validation_requires_every_identity_label() -> None:
    value = ownership()
    inspection = {"Id": "d" * 64, "Config": {"Labels": labels(value)}}
    runner = RecordingRunner()
    runner.responses = [Result(("docker",), 0, json.dumps([inspection]), "")]
    docker = Docker(runner)
    record = ResourceRecord("container", "app", "d" * 64)
    assert docker.validate_owned(record, value)["Id"] == "d" * 64
    for key in (OWNER, LAB, MANIFEST, MANIFEST_VERSION, RUN, CREATED, TRUSTED):
        broken = json.loads(json.dumps(inspection))
        broken["Config"]["Labels"][key] = "wrong"
        runner.responses = [Result(("docker",), 0, json.dumps([broken]), "")]
        with pytest.raises(PolicyError, match="ownership labels mismatch"):
            docker.validate_owned(record, value)


def test_remaining_bounded_docker_operations_construct_exact_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = RecordingRunner()
    runner.responses = [
        Result(("docker",), 0, '"26.1.5"\n', ""),
        Result(("docker",), 0, "2.40.0\n", ""),
    ]
    docker = Docker(runner, Timeouts(stop=2))
    assert docker.preflight() == {"engine": "26.1.5", "compose_v2": True}
    container = ResourceRecord("container", "app", "d" * 64)
    network = ResourceRecord("network", "net", "e" * 64)
    docker.connect_network(network, container)
    docker.start(container)
    docker.stop(container)
    runner.responses = [Result(("docker",), 0, "line\n", "warning\n")]
    assert docker.logs(container, follow=True).stdout == "line\n"
    docker.remove_image("example/app@sha256:" + "f" * 64)
    runner.responses = [
        Result(("docker",), 0, "one\n", ""),
        Result(("docker",), 0, "two\n", ""),
        Result(("docker",), 0, "three\n", ""),
    ]
    assert docker.managed_resources() == {
        "container": ("one",),
        "network": ("two",),
        "volume": ("three",),
    }
    assert ("docker", "network", "connect", "e" * 64, "d" * 64) in runner.calls
    assert not any("system" in call for argv in runner.calls for call in argv)


def test_inspection_and_preflight_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = RecordingRunner()
    docker = Docker(runner)
    with pytest.raises(ValueError, match="unsupported"):
        docker.inspect("service", "x")
    runner.responses = [Result(("docker",), 0, "not json", "")]
    with pytest.raises(IntegrityError, match="invalid"):
        docker.inspect("container", "d" * 64)
    runner.responses = [Result(("docker",), 0, "[]", "")]
    with pytest.raises(IntegrityError, match="unexpected"):
        docker.inspect("container", "d" * 64)
    runner.responses = [Result(("docker",), 1, "", "missing")]
    assert not docker.exists("container", "d" * 64)
    monkeypatch.setattr("vulndockyard.docker.shutil.which", lambda name: None)
    with pytest.raises(Exception, match="not installed"):
        docker.preflight()

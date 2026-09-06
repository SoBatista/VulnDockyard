from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

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
    DockerConnection,
    Ownership,
    Timeouts,
)
from vulndockyard.errors import IntegrityError, PolicyError, PreflightError
from vulndockyard.process import Result, Runner
from vulndockyard.state import ResourceRecord


class RecordingRunner(Runner):
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.environments: list[Mapping[str, str] | None] = []
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
        self.environments.append(env)
        if self.responses:
            return self.responses.pop(0)
        return Result(call, 0, "a" * 64 + "\n", "")


def test_timeout_environment_is_bounded_and_configurable() -> None:
    configured = Timeouts.discover({"VDY_TIMEOUT_PULL": "42"})
    assert configured.pull == 42
    assert configured.health == 120
    with pytest.raises(PreflightError, match="must be numeric"):
        Timeouts.discover({"VDY_TIMEOUT_PULL": "forever"})
    with pytest.raises(PreflightError, match="between"):
        Timeouts.discover({"VDY_TIMEOUT_CLEANUP": "0"})


def ownership() -> Ownership:
    return Ownership("juice-shop", "b" * 64, "c" * 32, "2026-09-06T00:00:00Z", True)


def fake_connection() -> DockerConnection:
    return DockerConnection("docker", Path("/var/run/docker.sock"))


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
    docker = Docker(
        runner,
        Timeouts(),
        connection=fake_connection(),
        environment={
            "DOCKER_CONFIG": "/attacker",
            "DOCKER_CONTEXT": "remote",
            "DOCKER_HOST": "tcp://attacker.invalid:2375",
            "HTTP_PROXY": "http://attacker.invalid",
        },
    )
    record = docker.create_application(
        name="vdy-juice-app",
        image="registry.example.test/app@sha256:" + "1" * 64,
        network="vdy-network",
        ownership=ownership(),
        memory_mb=512,
        cpus=0.5,
        pids=256,
        read_only=False,
    )
    call = runner.calls[-1]
    assert record.object_id == "a" * 64
    assert call[:5] == (
        "docker",
        "--host",
        "unix:///var/run/docker.sock",
        "container",
        "create",
    )
    assert "--publish" not in call
    assert (call[call.index("--restart")], call[call.index("--restart") + 1]) == ("--restart", "no")
    assert call[call.index("--cap-drop") + 1] == "ALL"
    assert call[call.index("--security-opt") + 1] == "no-new-privileges=true"
    assert call[call.index("--memory") + 1] == "512m"
    assert call[call.index("--memory-swap") + 1] == "512m"
    assert call[call.index("--log-driver") + 1] == "local"
    assert [call[index + 1] for index, value in enumerate(call) if value == "--log-opt"] == [
        "max-size=10m",
        "max-file=2",
    ]
    assert "--privileged" not in call
    assert runner.environments[-1] == fake_connection().environment()


def test_gateway_command_binds_only_loopback_and_fixed_target() -> None:
    runner = RecordingRunner()
    docker = Docker(runner, connection=fake_connection())
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
    assert call[call.index("--user") + 1] == "1000:1000"
    assert call[call.index("--cap-add") + 1] == "NET_BIND_SERVICE"
    assert call[call.index("--memory") + 1] == "128m"
    assert call[call.index("--memory-swap") + 1] == "128m"
    assert call[call.index("--log-driver") + 1] == "local"
    assert [call[index + 1] for index, value in enumerate(call) if value == "--log-opt"] == [
        "max-size=10m",
        "max-file=2",
    ]
    tmpfs_values = [call[index + 1] for index, value in enumerate(call) if value == "--tmpfs"]
    assert all("uid=1000,gid=1000,mode=0700" in value for value in tmpfs_values)
    assert list(call[-6:]) == ["caddy", "reverse-proxy", "--from", ":8080", "--to", "app:3000"]

    with pytest.raises(PolicyError, match="valid range"):
        docker.create_gateway(
            name="vdy-gateway",
            image="docker.io/library/caddy@sha256:" + "2" * 64,
            network="vdy-ingress",
            upstream_port=3000,
            host_port=True,
            ownership=ownership(),
        )


def test_network_and_cleanup_commands_are_scoped() -> None:
    runner = RecordingRunner()
    docker = Docker(runner, connection=fake_connection())
    network = docker.create_network("vdy-net", ownership(), internal=True)
    assert "--internal" in runner.calls[-1]
    docker.remove(ResourceRecord("container", "app", "d" * 64))
    assert runner.calls[-1] == (
        "docker",
        "--host",
        "unix:///var/run/docker.sock",
        "container",
        "rm",
        "--force",
        "d" * 64,
    )
    docker.remove(network)
    assert list(runner.calls[-1]) == [
        "docker",
        "--host",
        "unix:///var/run/docker.sock",
        "network",
        "rm",
        "a" * 64,
    ]
    assert all("prune" not in call for argv in runner.calls for call in argv)


def test_pull_requires_digest_and_verifies_repository_identity() -> None:
    runner = RecordingRunner()
    docker = Docker(runner, connection=fake_connection())
    with pytest.raises(PolicyError, match="immutable"):
        docker.pull("registry.example.test/app:latest")
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


@pytest.mark.parametrize(
    "reference",
    [
        "--host@sha256:" + "1" * 64,
        "example/app@sha256:" + "1" * 64,
        "registry.example.test/app@sha256:" + "1" * 63,
        "registry.example.test/app@sha256:" + "1" * 64 + "\n--privileged",
        "registry.example.test/app@@sha256:" + "1" * 64,
    ],
)
def test_all_image_argv_boundaries_reject_noncanonical_references(reference: str) -> None:
    runner = RecordingRunner()
    docker = Docker(runner, connection=fake_connection())
    with pytest.raises(PolicyError, match="canonical fully-qualified"):
        docker.pull(reference)
    with pytest.raises(PolicyError, match="canonical fully-qualified"):
        docker.create_application(
            name="vdy-app",
            image=reference,
            network="vdy-network",
            ownership=ownership(),
            memory_mb=512,
            cpus=0.5,
            pids=256,
            read_only=False,
        )
    with pytest.raises(PolicyError, match="canonical fully-qualified"):
        docker.create_gateway(
            name="vdy-gateway",
            image=reference,
            network="vdy-ingress",
            upstream_port=3000,
            host_port=18080,
            ownership=ownership(),
        )
    with pytest.raises(PolicyError, match="canonical fully-qualified"):
        docker.remove_image(reference)
    assert runner.calls == []


def test_ownership_validation_requires_every_identity_label() -> None:
    value = ownership()
    name = "vdy-juice-shop-cccccccccccc-app"
    inspection = {"Id": "d" * 64, "Name": f"/{name}", "Config": {"Labels": labels(value)}}
    runner = RecordingRunner()
    runner.responses = [Result(("docker",), 0, json.dumps([inspection]), "")]
    docker = Docker(runner, connection=fake_connection())
    record = ResourceRecord("container", name, "d" * 64)
    assert docker.validate_owned(record, value)["Id"] == "d" * 64
    for key in (OWNER, LAB, MANIFEST, MANIFEST_VERSION, RUN, CREATED, TRUSTED):
        broken = json.loads(json.dumps(inspection))
        broken["Config"]["Labels"][key] = "wrong"
        runner.responses = [Result(("docker",), 0, json.dumps([broken]), "")]
        with pytest.raises(PolicyError, match="ownership labels mismatch"):
            docker.validate_owned(record, value)
    wrong_name = json.loads(json.dumps(inspection))
    wrong_name["Name"] = "/unrelated"
    runner.responses = [Result(("docker",), 0, json.dumps([wrong_name]), "")]
    with pytest.raises(PolicyError, match="name mismatch"):
        docker.validate_owned(record, value)
    wrong_role = json.loads(json.dumps(inspection))
    wrong_role["Config"]["Labels"]["org.vulndockyard.role"] = "gateway"
    runner.responses = [Result(("docker",), 0, json.dumps([wrong_role]), "")]
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
    docker = Docker(runner, Timeouts(stop=2), connection=fake_connection())
    monkeypatch.setattr("vulndockyard.docker.platform.system", lambda: "Linux")
    monkeypatch.setattr("vulndockyard.docker.platform.machine", lambda: "x86_64")
    assert docker.preflight() == {
        "engine": "26.1.5",
        "compose_v2": True,
        "platform": "linux/amd64",
    }
    container = ResourceRecord("container", "app", "d" * 64)
    network = ResourceRecord("network", "net", "e" * 64)
    docker.connect_network(network, container)
    docker.start(container)
    docker.stop(container)
    runner.responses = [Result(("docker",), 0, "line\n", "warning\n")]
    assert docker.logs(container, follow=True).stdout == "line\n"
    docker.remove_image("registry.example.test/app@sha256:" + "f" * 64)
    runner.responses = [
        Result(("docker",), 0, "1" * 64 + "\n", ""),
        Result(("docker",), 0, "2" * 64 + "\n", ""),
        Result(("docker",), 0, "vdy-volume\n", ""),
    ]
    assert docker.managed_resources() == {
        "container": ("1" * 64,),
        "network": ("2" * 64,),
        "volume": ("vdy-volume",),
    }
    assert (
        "docker",
        "--host",
        "unix:///var/run/docker.sock",
        "network",
        "connect",
        "e" * 64,
        "d" * 64,
    ) in runner.calls
    assert not any("system" in call for argv in runner.calls for call in argv)


def test_inspection_and_preflight_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = RecordingRunner()
    docker = Docker(runner, connection=fake_connection())
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
    docker = Docker(runner, environment={"PATH": "/missing"})
    monkeypatch.setattr("vulndockyard.docker.shutil.which", lambda name, path=None: None)
    with pytest.raises(Exception, match="not installed"):
        docker.preflight()


def test_preflight_rejects_an_unsupported_local_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = Docker(RecordingRunner(), connection=fake_connection())
    monkeypatch.setattr("vulndockyard.docker.platform.system", lambda: "Darwin")
    monkeypatch.setattr("vulndockyard.docker.platform.machine", lambda: "arm64")
    with pytest.raises(PreflightError, match="unsupported local Docker platform"):
        docker.preflight()


def test_connection_accepts_only_a_local_unix_socket_and_sanitizes_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = tmp_path / "docker.sock"
    socket_path.touch()
    monkeypatch.setattr("vulndockyard.docker.shutil.which", lambda name, path=None: "/bin/true")
    monkeypatch.setattr("vulndockyard.docker.stat.S_ISSOCK", lambda mode: True)
    connection = DockerConnection.discover(
        {
            "PATH": "/usr/bin",
            "DOCKER_HOST": f"unix://{socket_path}",
            "DOCKER_CONFIG": "/attacker/config",
            "HTTP_PROXY": "http://attacker.invalid",
        }
    )
    assert connection.socket == socket_path
    environment = connection.environment()
    assert environment["DOCKER_HOST"] == f"unix://{socket_path}"
    assert "DOCKER_CONFIG" not in environment
    assert "HTTP_PROXY" not in environment
    socket_path.chmod(0o666)
    with pytest.raises(PreflightError, match="world-writable"):
        DockerConnection.discover({"PATH": "/usr/bin", "DOCKER_HOST": f"unix://{socket_path}"})


@pytest.mark.parametrize(
    "environment",
    (
        {"PATH": "/usr/bin", "DOCKER_HOST": "tcp://127.0.0.1:2375"},
        {"PATH": "/usr/bin", "DOCKER_CONTEXT": "remote"},
        {"PATH": "/usr/bin", "VDY_DOCKER_SOCKET": "relative.sock"},
        {
            "PATH": "/usr/bin",
            "VDY_DOCKER_SOCKET": "/var/run/docker.sock",
            "DOCKER_HOST": "unix:///var/run/docker.sock",
        },
    ),
)
def test_connection_rejects_remote_or_ambiguous_endpoints(
    environment: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulndockyard.docker.shutil.which", lambda name, path=None: "/bin/true")
    with pytest.raises(PreflightError):
        DockerConnection.discover(environment)

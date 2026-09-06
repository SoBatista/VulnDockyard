from __future__ import annotations

import pytest

from vulndockyard.compose_policy import load_compose, validate_compose
from vulndockyard.errors import IntegrityError

DIGEST = "sha256:" + "a" * 64
IMAGE = f"registry.example.test/lab@{DIGEST}"


def safe_document() -> dict[str, object]:
    return {
        "name": "reviewed",
        "services": {
            "app": {
                "image": IMAGE,
                "restart": "no",
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "user": "1000:1000",
                "read_only": True,
                "volumes": ["data:/var/lib/lab"],
                "ports": [],
                "networks": ["app"],
                "deploy": {"resources": {"limits": {"memory": "512M", "cpus": "0.5", "pids": 256}}},
            }
        },
        "volumes": {"data": {}},
        "networks": {"app": {"internal": True}},
    }


def test_safe_reviewed_structure_is_accepted() -> None:
    review = validate_compose(safe_document(), approved_images={IMAGE})
    assert review.accepted
    assert review.findings == ()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("privileged", True),
        ("network_mode", "host"),
        ("pid", "host"),
        ("ipc", "host"),
        ("userns_mode", "host"),
        ("devices", ["/dev/kvm"]),
        ("build", "."),
        ("extends", {"file": "other.yml"}),
        ("sysctls", {"kernel.shmmax": "1"}),
        ("runtime", "runc"),
        ("env_file", ".env"),
        ("container_name", "unscoped-name"),
    ],
)
def test_dangerous_compose_features_are_rejected(key: str, value: object) -> None:
    document = safe_document()
    document["services"]["app"][key] = value  # type: ignore[index]
    review = validate_compose(document, approved_images={IMAGE})
    assert not review.accepted
    assert any(finding.path == f"services.app.{key}" for finding in review.findings)


def test_host_bind_socket_and_unbounded_ports_are_rejected() -> None:
    document = safe_document()
    service = document["services"]["app"]  # type: ignore[index]
    service["volumes"] = ["/var/run/docker.sock:/var/run/docker.sock"]
    service["ports"] = ["8080:80"]
    review = validate_compose(document, approved_images={IMAGE})
    reasons = " ".join(finding.reason for finding in review.findings)
    assert "declared named volumes" in reasons
    assert "loopback gateway" in reasons


def test_unverified_mutable_image_and_command_are_rejected() -> None:
    document = safe_document()
    service = document["services"]["app"]  # type: ignore[index]
    service["image"] = "example/lab:latest"
    service["command"] = ["sh", "-c", "touch /host/file"]
    review = validate_compose(document, approved_images=set())
    assert not review.accepted
    assert {finding.path for finding in review.findings} >= {
        "services.app.image",
        "services.app.command",
    }


def test_interpolation_and_extensions_are_rejected() -> None:
    document = safe_document()
    document["x-evil"] = {"value": "${HOME}"}
    review = validate_compose(document, approved_images={IMAGE})
    assert not review.accepted
    assert any("interpolation" in finding.reason for finding in review.findings)
    assert any("extension" in finding.reason for finding in review.findings)


def test_external_network_volume_and_writable_root_are_rejected() -> None:
    document = safe_document()
    document["networks"] = {"app": {"external": True}}
    document["volumes"] = {"data": {"name": "host-data"}}
    document["services"]["app"]["read_only"] = False  # type: ignore[index]
    review = validate_compose(document, approved_images={IMAGE})
    reasons = " ".join(finding.reason for finding in review.findings)
    assert "internal" in reasons
    assert "driver-configured" in reasons
    assert "read-only" in reasons


@pytest.mark.parametrize(
    ("mutation", "path"),
    [
        (
            lambda service: service.update(
                {"security_opt": ["no-new-privileges:true", "seccomp:unconfined"]}
            ),
            "services.app.security_opt",
        ),
        (lambda service: service.update({"user": "root"}), "services.app.user"),
        (lambda service: service.update({"user": "0:0"}), "services.app.user"),
        (lambda service: service.update({"user": "9999999999"}), "services.app.user"),
        (lambda service: service.update({"restart": "none"}), "services.app.restart"),
        (lambda service: service.update({"init": False}), "services.app.init"),
        (
            lambda service: service["deploy"]["resources"]["limits"].pop("pids"),
            "services.app.deploy.resources.limits",
        ),
        (
            lambda service: service["deploy"]["resources"]["limits"].update({"cpus": 0}),
            "services.app.deploy.resources.limits",
        ),
        (
            lambda service: service["deploy"]["resources"]["limits"].update({"memory": "0M"}),
            "services.app.deploy.resources.limits",
        ),
        (
            lambda service: service["deploy"]["resources"].update(
                {"reservations": {"memory": "1M"}}
            ),
            "services.app.deploy.resources.limits",
        ),
    ],
)
def test_identity_security_and_resource_limits_fail_closed(mutation: object, path: str) -> None:
    document = safe_document()
    service = document["services"]["app"]  # type: ignore[index]
    mutation(service)  # type: ignore[operator]
    review = validate_compose(document, approved_images={IMAGE})
    assert not review.accepted
    assert any(finding.path == path for finding in review.findings)


def test_capability_port_and_volume_extras_are_rejected() -> None:
    document = safe_document()
    service = document["services"]["app"]  # type: ignore[index]
    service["cap_drop"] = ["ALL", "NET_RAW"]
    service["volumes"] = [
        {"type": "volume", "source": "data", "target": "/data", "volume": {"evil": True}}
    ]
    service["ports"] = [
        {"host_ip": "127.0.0.1", "published": 8080, "target": 80, "protocol": "udp"}
    ]
    review = validate_compose(document, approved_images={IMAGE})
    paths = {finding.path for finding in review.findings}
    assert {
        "services.app.cap_drop",
        "services.app.volumes",
        "services.app.ports",
    } <= paths


def test_unhashable_capabilities_and_networks_are_rejected_without_crashing() -> None:
    document = safe_document()
    service = document["services"]["app"]  # type: ignore[index]
    service["cap_add"] = [{"capability": "ALL"}]
    service["networks"] = [{"target": "app"}]
    review = validate_compose(document, approved_images={IMAGE})
    paths = {finding.path for finding in review.findings}
    assert {"services.app.cap_add", "services.app.networks"} <= paths


def test_yaml_parser_is_bounded_and_fail_closed() -> None:
    assert load_compose(b"services:\n  app:\n    image: x\n")["services"]
    with pytest.raises(IntegrityError, match="NUL"):
        load_compose(b"services:\x00")
    with pytest.raises(IntegrityError, match="invalid"):
        load_compose(b"services: [")
    with pytest.raises(IntegrityError, match="2 MB"):
        load_compose(b"x" * 2_000_001)
    with pytest.raises(IntegrityError, match="duplicate key"):
        load_compose(b"services: {}\nservices: {}\n")
    with pytest.raises(IntegrityError, match="anchors and aliases"):
        load_compose(b"services: &services {}\ncopy: *services\n")


def test_legacy_compose_version_is_recognized_but_malformed_version_is_rejected() -> None:
    document = safe_document()
    document["version"] = "3.8"
    assert validate_compose(document, approved_images={IMAGE}).accepted
    document["version"] = "latest"
    review = validate_compose(document, approved_images={IMAGE})
    assert any(finding.path == "version" for finding in review.findings)

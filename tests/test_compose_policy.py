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
                "read_only": True,
                "volumes": ["data:/var/lib/lab"],
                "ports": [],
                "networks": ["app"],
                "deploy": {"resources": {"limits": {"memory": "512M", "cpus": "0.5"}}},
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


def test_yaml_parser_is_bounded_and_fail_closed() -> None:
    assert load_compose(b"services:\n  app:\n    image: x\n")["services"]
    with pytest.raises(IntegrityError, match="NUL"):
        load_compose(b"services:\x00")
    with pytest.raises(IntegrityError, match="invalid"):
        load_compose(b"services: [")
    with pytest.raises(IntegrityError, match="2 MB"):
        load_compose(b"x" * 2_000_001)

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from vulndockyard.catalogue import Catalogue, canonical_json, identity, template_identity
from vulndockyard.errors import IntegrityError, NotFoundError
from vulndockyard.models import Lockfile, Manifest

EXPECTED = {
    "juice-shop",
    "webgoat",
    "crapi",
    "dvwa",
    "bwapp",
    "mutillidae",
    "vampi",
    "dvga",
    "wrongsecrets",
    "nodegoat",
    "railsgoat",
    "security-shepherd",
}


def test_catalogue_has_exact_initial_inventory() -> None:
    labs = Catalogue().validate()
    assert {lab.manifest.id for lab in labs} == EXPECTED
    assert [lab.manifest.id for lab in labs] == sorted(EXPECTED)
    assert [lab.manifest.id for lab in labs if lab.manifest.adapter_status.value == "runnable"] == [
        "juice-shop"
    ]


def test_runnable_images_are_digest_pinned_and_locked() -> None:
    for lab in Catalogue().all():
        if lab.manifest.adapter_status.value != "runnable":
            continue
        assert lab.manifest.trust.value != "quarantined"
        assert lab.manifest.images
        assert {(image.name, image.digest) for image in lab.manifest.images} == {
            (image.name, image.digest) for image in lab.lock.images
        }
        assert all(image.reference.count("@sha256:") == 1 for image in lab.manifest.images)
        assert lab.lock.template_sha256 == template_identity(lab.manifest)


def test_juice_shop_records_the_gateway_only_caddy_capability_exception() -> None:
    capabilities = Catalogue().get("juice-shop").manifest.raw["dangerous_capabilities"]
    assert capabilities == [
        "gateway: CAP_NET_BIND_SERVICE only; required to execute the locked official Caddy "
        "binary after cap_drop=ALL"
    ]


def test_juice_shop_declares_only_bounded_owned_ephemeral_storage() -> None:
    manifest = Catalogue().get("juice-shop").manifest
    raw = manifest.raw
    storage = raw["ephemeral_storage"]
    assert storage["uid"] == 65532
    assert storage["gid"] == 65532
    assert {
        (mount["name"], mount["container_path"], mount["size_mb"]) for mount in storage["seeded"]
    } == {
        ("data", "/juice-shop/data", 64),
        ("ftp", "/juice-shop/ftp", 32),
        ("frontend", "/juice-shop/frontend/dist/frontend", 64),
        ("csaf", "/juice-shop/.well-known/csaf", 2),
    }
    assert {
        (mount["name"], mount["container_path"], mount["size_mb"]) for mount in storage["empty"]
    } == {
        ("i18n", "/juice-shop/i18n", 16),
        ("logs", "/juice-shop/logs", 16),
        ("uploads-complaints", "/juice-shop/uploads/complaints", 16),
        ("tmp", "/tmp", 16),  # noqa: S108 - reviewed in-container scratch mount
    }
    assert raw["resources"]["read_only_root"] is True
    assert raw["persistence"] == {
        "required": False,
        "volumes": [
            "data",
            "ftp",
            "frontend",
            "csaf",
            "i18n",
            "logs",
            "uploads-complaints",
            "tmp",
        ],
    }
    assert manifest.persistence_required is False
    assert manifest.persistence_volumes == (
        "data",
        "ftp",
        "frontend",
        "csaf",
        "i18n",
        "logs",
        "uploads-complaints",
        "tmp",
    )


def test_runnable_persistent_storage_requires_an_exact_root_owned_mount_set(
    juice_shop: object,
) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw["ephemeral_storage"].update({"uid": 0, "gid": 0})
    raw["persistence"]["required"] = True

    manifest = Manifest.parse(raw)

    assert manifest.persistence_required is True
    assert manifest.persistence_volumes == tuple(raw["persistence"]["volumes"])


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: (
                value["ephemeral_storage"].update({"uid": 0, "gid": 0}),
                value["persistence"].update({"required": True, "volumes": ["data"]}),
            ),
            "exactly identify declared writable storage",
        ),
        (
            lambda value: (
                value["ephemeral_storage"].update({"uid": 0, "gid": 0, "seeded": [], "empty": []}),
                value["persistence"].update({"required": True, "volumes": []}),
            ),
            "at least one declared writable mount",
        ),
        (
            lambda value: value["persistence"].update({"required": True}),
            "storage uid and gid 0",
        ),
    ],
)
def test_runnable_persistent_storage_contract_fails_closed(
    mutation: object, message: str, juice_shop: object
) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    mutation(raw)  # type: ignore[operator]
    with pytest.raises(IntegrityError, match=message):
        Manifest.parse(raw)


def test_quarantined_persistence_metadata_does_not_require_runnable_storage_contract() -> None:
    catalogue = Catalogue()
    bwapp = catalogue.get("bwapp").manifest
    shepherd = catalogue.get("security-shepherd").manifest

    assert bwapp.persistence_required is True
    assert bwapp.persistence_volumes == ("database", "application-writes")
    assert shepherd.persistence_required is True
    assert shepherd.persistence_volumes == ()


def test_quarantined_labs_have_explicit_empty_ephemeral_storage_contracts() -> None:
    for lab in Catalogue().all():
        if lab.manifest.adapter_status.value == "runnable":
            continue
        assert lab.manifest.raw["ephemeral_storage"] == {
            "uid": 0,
            "gid": 0,
            "seeded": [],
            "empty": [],
        }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["ephemeral_storage"].update({"uid": True}), "uid"),
        (lambda value: value["ephemeral_storage"].update({"gid": -1}), "gid"),
        (
            lambda value: value["ephemeral_storage"]["seeded"][0].update({"extra": "unsafe"}),
            "unknown extra",
        ),
        (
            lambda value: value["ephemeral_storage"]["seeded"][0].update(
                {"container_path": "juice-shop/data"}
            ),
            "absolute normalized",
        ),
        (
            lambda value: value["ephemeral_storage"]["seeded"][0].update(
                {"container_path": "/juice-shop/../data"}
            ),
            "absolute normalized",
        ),
        (
            lambda value: value["ephemeral_storage"]["seeded"][0].update(
                {"container_path": "/juice-shop/data\n"}
            ),
            "absolute normalized",
        ),
        (
            lambda value: value["ephemeral_storage"]["empty"][0].update({"name": "data"}),
            "unique and disjoint",
        ),
        (
            lambda value: value["ephemeral_storage"]["empty"][0].update(
                {"container_path": "/juice-shop/data"}
            ),
            "paths must be unique",
        ),
        (
            lambda value: value["ephemeral_storage"]["empty"][0].update(
                {"container_path": "/juice-shop/data/cache"}
            ),
            "paths must not overlap",
        ),
        (
            lambda value: value["ephemeral_storage"]["empty"][0].update({"size_mb": 0}),
            "size_mb",
        ),
        (
            lambda value: value["ephemeral_storage"]["empty"][0].update({"size_mb": True}),
            "size_mb",
        ),
    ],
)
def test_ephemeral_storage_contract_fails_closed(
    mutation: object, message: str, juice_shop: object
) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    mutation(raw)  # type: ignore[operator]
    with pytest.raises(IntegrityError, match=message):
        Manifest.parse(raw)


def test_template_identity_binds_ephemeral_storage(juice_shop: object) -> None:
    manifest = juice_shop.manifest  # type: ignore[attr-defined]
    raw = copy.deepcopy(manifest.raw)
    raw["ephemeral_storage"]["empty"][0]["size_mb"] += 1
    assert template_identity(Manifest.parse(raw)) != template_identity(manifest)


def test_quarantined_lab_refuses_image_reference() -> None:
    lab = Catalogue().get("bwapp")
    assert lab.manifest.adapter_status.value == "quarantined"
    assert "redistribution" in lab.manifest.status_reason


def test_quarantined_adapter_evidence_matches_pinned_upstream_topologies() -> None:
    catalogue = Catalogue()

    bwapp = catalogue.get("bwapp").manifest.raw
    assert bwapp["license"]["spdx"] == "NOASSERTION"
    assert "reserve all rights" in bwapp["license"]["redistribution"]

    shepherd = catalogue.get("security-shepherd").manifest.raw
    assert shepherd["version"]["tag"] == "v3.1"
    assert shepherd["persistence"]["volumes"] == []
    assert shepherd["reset"]["effects"] == ["web-container-state", "mysql-container-state"]
    assert "Mongo" not in shepherd["trust"]["status_reason"]

    nodegoat = catalogue.get("nodegoat").manifest.raw
    assert "Node 4.4" in nodegoat["trust"]["status_reason"]
    assert "mongo:latest" in nodegoat["trust"]["status_reason"]

    wrongsecrets = catalogue.get("wrongsecrets").manifest.raw
    assert wrongsecrets["license"]["spdx"] == "AGPL-3.0-or-later"
    assert {
        (service["name"], service["internal_port"]) for service in wrongsecrets["services"]
    } == {
        ("web", 8080),
        ("mcp", 8090),
    }

    mutillidae = catalogue.get("mutillidae").manifest.raw
    assert {image["role"] for image in mutillidae["images"]} == {
        "application",
        "database",
        "database-admin",
        "directory",
        "directory-admin",
    }
    assert mutillidae["persistence"]["volumes"] == ["ldap_data", "ldap_config"]

    crapi = catalogue.get("crapi").manifest.raw
    assert len(crapi["images"]) == 10
    assert len(crapi["services"]) == 10
    assert {"postgresql-data", "mongodb-data", "chromadb-data"} < set(
        crapi["persistence"]["volumes"]
    )


def test_lookup_search_and_ambiguity() -> None:
    catalogue = Catalogue()
    assert catalogue.get("Juice Shop").manifest.id == "juice-shop"
    assert {lab.manifest.id for lab in catalogue.search("graphql")} == {"dvga"}
    with pytest.raises(NotFoundError, match="unknown lab"):
        catalogue.get("does-not-exist")
    with pytest.raises(NotFoundError, match="ambiguous"):
        catalogue.get("goat")


def test_canonical_identity_is_deterministic() -> None:
    first = {"b": 2, "a": [1]}
    second = {"a": [1], "b": 2}
    assert canonical_json(first) == b'{"a":[1],"b":2}\n'
    assert identity(first) == identity(second)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"surprise": True}), "unknown surprise"),
        (lambda value: value.pop("trust"), "missing trust"),
        (lambda value: value.update({"friendly_hostname": "unsafe.local"}), "reserved .test"),
        (lambda value: value["upstream"].update({"repository": "file:///tmp/source"}), "https URL"),
        (lambda value: value["version"].update({"commit": "abc"}), "full lowercase"),
        (lambda value: value["images"][0].update({"digest": "sha256:bad"}), "immutable sha256"),
        (
            lambda value: value["images"][0].update(
                {"name": "--platform=linux/amd64@sha256:unsafe"}
            ),
            "canonical fully qualified OCI repository",
        ),
        (lambda value: value.update({"runtime_backend": "shell"}), "docker-engine"),
    ],
)
def test_manifest_fails_closed(mutation: object, message: str, juice_shop: object) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    mutation(raw)  # type: ignore[operator]
    with pytest.raises(IntegrityError, match=message):
        Manifest.parse(raw)


def test_non_runnable_cannot_claim_trust(juice_shop: object) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw["adapter_status"] = "quarantined"
    with pytest.raises(IntegrityError, match="must use quarantined trust"):
        Manifest.parse(raw)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["trust"].update({"level": "invented"}), "trust.level"),
        (lambda value: value.update({"adapter_status": "maybe"}), "adapter_status"),
        (lambda value: value.update({"last_verified": "2026-02-30"}), "last_verified"),
        (lambda value: value.update({"last_verified": "20260906"}), "last_verified"),
    ],
)
def test_manifest_enum_and_date_errors_are_integrity_failures(
    mutation: object, message: str, juice_shop: object
) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    mutation(raw)  # type: ignore[operator]
    with pytest.raises(IntegrityError, match=message):
        Manifest.parse(raw)


def test_runnable_trust_invariants_fail_closed(juice_shop: object) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw["trust"]["limitations"] = []
    with pytest.raises(IntegrityError, match="provenance limitation"):
        Manifest.parse(raw)

    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw["version"]["commit"] = ""
    with pytest.raises(IntegrityError, match="pinned upstream commit"):
        Manifest.parse(raw)

    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw["images"][0]["architectures"] = []
    with pytest.raises(IntegrityError, match="architecture-qualified"):
        Manifest.parse(raw)

    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw["resources"]["read_only_root"] = False
    with pytest.raises(IntegrityError, match="read-only root filesystem"):
        Manifest.parse(raw)


def test_service_identity_is_a_bounded_literal_marker(juice_shop: object) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw["services"][0]["identity_marker"] = "x" * 161
    with pytest.raises(IntegrityError, match="printable literal"):
        Manifest.parse(raw)

    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw["services"][0]["identity_marker"] = "unsafe\nmarker"
    with pytest.raises(IntegrityError, match="printable literal"):
        Manifest.parse(raw)


def test_runnable_cannot_omit_digest(juice_shop: object) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw["images"][0]["digest"] = ""
    with pytest.raises(IntegrityError, match="digest-pinned"):
        Manifest.parse(raw)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["services"][0].update({"health_path": "//remote.example/"}),
            "origin-relative",
        ),
        (
            lambda value: value["services"][0].update({"protocol": "tcp"}),
            "HTTP application health",
        ),
        (
            lambda value: value["services"].append(copy.deepcopy(value["services"][0])),
            "service names must be unique",
        ),
        (
            lambda value: value["images"].append(
                {
                    "name": "registry.example.test/extra",
                    "digest": "sha256:" + "e" * 64,
                    "architectures": ["linux/amd64"],
                    "role": "extra",
                }
            ),
            "exactly one application",
        ),
        (
            lambda value: value["services"][1].update({"internal_port": 3001}),
            "share one internal port",
        ),
        (
            lambda value: value["initialization"].update({"automatic": False}),
            "automatic initialization",
        ),
        (
            lambda value: value["resources"].update({"memory_mb": 20_000}),
            "memory_mb",
        ),
    ],
)
def test_runnable_runtime_contract_fails_closed(
    mutation: object, message: str, juice_shop: object
) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    mutation(raw)  # type: ignore[operator]
    with pytest.raises(IntegrityError, match=message):
        Manifest.parse(raw)


def test_lockfile_rejects_mutable_or_unknown_content(juice_shop: object) -> None:
    raw = copy.deepcopy(juice_shop.lock.raw)  # type: ignore[attr-defined]
    raw["images"][0]["digest"] = ""
    with pytest.raises(IntegrityError, match="immutable digests"):
        Lockfile.parse(raw)
    raw = copy.deepcopy(juice_shop.lock.raw)  # type: ignore[attr-defined]
    raw["extra"] = "unexpected"
    with pytest.raises(IntegrityError, match="unknown extra"):
        Lockfile.parse(raw)

    raw = copy.deepcopy(juice_shop.lock.raw)  # type: ignore[attr-defined]
    raw["redistribution_status"] = "claimed"
    with pytest.raises(IntegrityError, match="redistribution_status"):
        Lockfile.parse(raw)

    raw = copy.deepcopy(juice_shop.lock.raw)  # type: ignore[attr-defined]
    raw["sbom_url"] = "file:///tmp/sbom.json"
    with pytest.raises(IntegrityError, match="sbom_url"):
        Lockfile.parse(raw)


@pytest.mark.parametrize("timestamp", ["2026-02-30T00:00:00Z", "2026-09-06", "2026-09-06T00:00:00"])
def test_lockfile_timestamp_must_be_valid_canonical_utc(timestamp: str, juice_shop: object) -> None:
    raw = copy.deepcopy(juice_shop.lock.raw)  # type: ignore[attr-defined]
    raw["verified_at"] = timestamp
    with pytest.raises(IntegrityError, match="UTC ISO 8601"):
        Lockfile.parse(raw)


def test_catalogue_rejects_manifest_lock_mismatch(tmp_path: Path, juice_shop: object) -> None:
    manifests = tmp_path / "manifests"
    locks = tmp_path / "locks"
    manifests.mkdir()
    locks.mkdir()
    raw_manifest = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw_lock = copy.deepcopy(juice_shop.lock.raw)  # type: ignore[attr-defined]
    raw_lock["images"][0]["digest"] = "sha256:" + "1" * 64
    (manifests / "juice-shop.json").write_text(json.dumps(raw_manifest), encoding="utf-8")
    (locks / "juice-shop.lock.json").write_text(json.dumps(raw_lock), encoding="utf-8")
    with pytest.raises(IntegrityError, match="manifest and lock images differ"):
        Catalogue(tmp_path).all()


def test_quarantined_digest_evidence_is_also_bound_to_its_lock(tmp_path: Path) -> None:
    manifests = tmp_path / "manifests"
    locks = tmp_path / "locks"
    manifests.mkdir()
    locks.mkdir()
    dvwa = Catalogue().get("dvwa")
    raw_manifest = copy.deepcopy(dvwa.manifest.raw)
    raw_lock = copy.deepcopy(dvwa.lock.raw)
    raw_lock["images"] = []
    (manifests / "dvwa.json").write_text(json.dumps(raw_manifest), encoding="utf-8")
    (locks / "dvwa.lock.json").write_text(json.dumps(raw_lock), encoding="utf-8")
    with pytest.raises(IntegrityError, match="manifest and lock images differ"):
        Catalogue(tmp_path).all()


def test_upstream_signed_requires_provenance_and_signature_lock_evidence(
    tmp_path: Path, juice_shop: object
) -> None:
    manifests = tmp_path / "manifests"
    locks = tmp_path / "locks"
    manifests.mkdir()
    locks.mkdir()
    raw_manifest = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw_manifest["trust"]["level"] = "upstream-signed"
    raw_lock = copy.deepcopy(juice_shop.lock.raw)  # type: ignore[attr-defined]
    (manifests / "juice-shop.json").write_text(json.dumps(raw_manifest), encoding="utf-8")
    (locks / "juice-shop.lock.json").write_text(json.dumps(raw_lock), encoding="utf-8")
    with pytest.raises(IntegrityError, match="lacks provenance or signature"):
        Catalogue(tmp_path).all()


def test_catalogue_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    manifests = tmp_path / "manifests"
    locks = tmp_path / "locks"
    manifests.mkdir()
    locks.mkdir()
    (manifests / "duplicate.json").write_text(
        '{"schema_version":1,"schema_version":1}\n', encoding="utf-8"
    )
    with pytest.raises(IntegrityError, match="duplicate JSON object key"):
        Catalogue(tmp_path).all()


def test_catalogue_binds_filenames_hostnames_and_lock_inventory(
    tmp_path: Path, juice_shop: object
) -> None:
    manifests = tmp_path / "manifests"
    locks = tmp_path / "locks"
    manifests.mkdir()
    locks.mkdir()
    raw_manifest = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw_lock = copy.deepcopy(juice_shop.lock.raw)  # type: ignore[attr-defined]
    (manifests / "wrong-name.json").write_text(json.dumps(raw_manifest), encoding="utf-8")
    (locks / "juice-shop.lock.json").write_text(json.dumps(raw_lock), encoding="utf-8")
    with pytest.raises(IntegrityError, match="filename"):
        Catalogue(tmp_path).all()

    (manifests / "wrong-name.json").rename(manifests / "juice-shop.json")
    (locks / "orphan.lock.json").write_text(json.dumps(raw_lock), encoding="utf-8")
    with pytest.raises(IntegrityError, match="inventories differ"):
        Catalogue(tmp_path).all()

    (locks / "orphan.lock.json").unlink()
    second = copy.deepcopy(raw_manifest)
    second["id"] = "second-lab"
    (manifests / "second-lab.json").write_text(json.dumps(second), encoding="utf-8")
    second_lock = copy.deepcopy(raw_lock)
    second_lock["lab_id"] = "second-lab"
    (locks / "second-lab.lock.json").write_text(json.dumps(second_lock), encoding="utf-8")
    with pytest.raises(IntegrityError, match="duplicate friendly hostnames"):
        Catalogue(tmp_path).all()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("lab_version", "20.2.1", "versions differ"),
        ("upstream_release", "v20.2.1", "versions differ"),
        ("upstream_commit", "1" * 40, "versions differ"),
        ("trust_evidence", ["https://example.test/different"], "trust evidence differ"),
        ("verified_platforms", ["linux/arm64"], "verified platforms differ"),
        ("verification_evidence", ["different smoke"], "verification evidence differ"),
        ("verified_at", "2026-09-07T00:00:00Z", "verification dates differ"),
        ("template_sha256", "sha256:" + "9" * 64, "orchestration template differs"),
    ],
)
def test_runnable_manifest_lock_metadata_is_bound(
    tmp_path: Path, juice_shop: object, field: str, value: object, message: str
) -> None:
    manifests = tmp_path / "manifests"
    locks = tmp_path / "locks"
    manifests.mkdir()
    locks.mkdir()
    raw_manifest = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw_lock = copy.deepcopy(juice_shop.lock.raw)  # type: ignore[attr-defined]
    raw_lock[field] = value
    (manifests / "juice-shop.json").write_text(json.dumps(raw_manifest), encoding="utf-8")
    (locks / "juice-shop.lock.json").write_text(json.dumps(raw_lock), encoding="utf-8")
    with pytest.raises(IntegrityError, match=message):
        Catalogue(tmp_path).all()


def test_vulndockyard_built_requires_build_evidence_and_ghcr(
    tmp_path: Path, juice_shop: object
) -> None:
    manifests = tmp_path / "manifests"
    locks = tmp_path / "locks"
    manifests.mkdir()
    locks.mkdir()
    raw_manifest = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw_manifest["trust"]["level"] = "vulndockyard-built"
    raw_lock = copy.deepcopy(juice_shop.lock.raw)  # type: ignore[attr-defined]
    (manifests / "juice-shop.json").write_text(json.dumps(raw_manifest), encoding="utf-8")
    (locks / "juice-shop.lock.json").write_text(json.dumps(raw_lock), encoding="utf-8")
    with pytest.raises(IntegrityError, match="lacks source, build, SBOM"):
        Catalogue(tmp_path).all()

    raw_lock["source_sha256"] = "sha256:" + "2" * 64
    raw_lock["build_recipe_revision"] = "recipes/juice-shop@1"
    raw_lock["sbom_url"] = "https://example.test/sbom.spdx.json"
    raw_lock["provenance_url"] = "https://example.test/provenance.json"
    raw_lock["signature_url"] = "https://example.test/signature"
    raw_lock["redistribution_status"] = "permitted"
    raw_lock["redistribution_evidence_url"] = "https://example.test/license-review"
    (locks / "juice-shop.lock.json").write_text(json.dumps(raw_lock), encoding="utf-8")
    with pytest.raises(IntegrityError, match="not hosted on GHCR"):
        Catalogue(tmp_path).all()

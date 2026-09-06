from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from vulndockyard.catalogue import Catalogue, canonical_json, identity
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


def test_quarantined_lab_refuses_image_reference() -> None:
    lab = Catalogue().get("bwapp")
    assert lab.manifest.adapter_status.value == "quarantined"
    assert "redistribution" in lab.manifest.status_reason


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


def test_runnable_cannot_omit_digest(juice_shop: object) -> None:
    raw = copy.deepcopy(juice_shop.manifest.raw)  # type: ignore[attr-defined]
    raw["images"][0]["digest"] = ""
    with pytest.raises(IntegrityError, match="digest-pinned"):
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

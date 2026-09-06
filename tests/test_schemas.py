from __future__ import annotations

import copy
import json
from importlib import resources
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from vulndockyard.catalogue import Catalogue
from vulndockyard.errors import IntegrityError
from vulndockyard.models import LOCK_KEYS, MANIFEST_KEYS, Lockfile, Manifest


def schema(name: str) -> dict[str, Any]:
    path = resources.files("vulndockyard").joinpath("data", "schemas", name)
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def validate_schema_instance(name: str, instance: object) -> None:
    document = schema(name)
    Draft202012Validator.check_schema(document)
    Draft202012Validator(document, format_checker=FormatChecker()).validate(instance)


def replace_at_path(document: dict[str, Any], path: tuple[str | int, ...], value: object) -> None:
    cursor: Any = document
    for component in path[:-1]:
        cursor = cursor[component]
    cursor[path[-1]] = copy.deepcopy(value)


def test_schemas_are_draft_2020_12_and_match_parser_required_fields() -> None:
    manifest = schema("manifest-v1.schema.json")
    lock = schema("lock-v1.schema.json")
    assert manifest["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert lock["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert set(manifest["required"]) == MANIFEST_KEYS
    assert set(lock["required"]) == LOCK_KEYS
    assert manifest["additionalProperties"] is False
    assert lock["additionalProperties"] is False


def test_all_packaged_manifests_and_locks_pass_authoritative_parser() -> None:
    catalogue = Catalogue()
    assert len(catalogue.all()) == 12


def test_all_packaged_manifests_and_locks_pass_json_schema() -> None:
    labs = Catalogue().all()
    for lab in labs:
        validate_schema_instance("manifest-v1.schema.json", lab.manifest.raw)
        validate_schema_instance("lock-v1.schema.json", lab.lock.raw)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(("version", "commit"), "", id="missing-commit"),
        pytest.param(("version", "tag"), "LATEST", id="mutable-latest-tag"),
        pytest.param(("trust", "level"), "quarantined", id="quarantined-trust"),
        pytest.param(("trust", "evidence"), [], id="missing-trust-evidence"),
        pytest.param(
            ("trust", "evidence"), ["http://example.test/evidence"], id="non-https-evidence"
        ),
        pytest.param(("trust", "limitations"), [], id="missing-pinned-limitation"),
        pytest.param(("images", 0, "architectures"), [], id="missing-architecture"),
        pytest.param(("images", 1, "role"), "application", id="missing-gateway-role"),
        pytest.param(("services", 0, "protocol"), "https", id="unsupported-service-protocol"),
        pytest.param(("services", 0, "health_path"), "/#fragment", id="fragment-health-path"),
        pytest.param(("health_check", "type"), "http", id="unsupported-health-type"),
        pytest.param(("initialization", "automatic"), False, id="manual-initialization"),
        pytest.param(("resources", "read_only_root"), False, id="writable-root"),
        pytest.param(("ephemeral_storage", "uid"), 0, id="root-storage-owner"),
        pytest.param(
            ("persistence", "volumes"), ["data", "data"], id="duplicate-persistence-volume"
        ),
        pytest.param(("verification", "status"), "blocked", id="blocked-verification"),
        pytest.param(("verification", "platforms"), [], id="missing-verified-platform"),
        pytest.param(
            ("verification", "platforms"),
            ["linux/s390x"],
            id="unsupported-verified-platform",
        ),
        pytest.param(("verification", "evidence"), [], id="missing-verification-evidence"),
        pytest.param(("last_verified",), "2026-02-30", id="invalid-calendar-date"),
    ],
)
def test_runnable_manifest_schema_matches_parser_rejections(
    path: tuple[str | int, ...], value: object
) -> None:
    raw = copy.deepcopy(Catalogue().get("juice-shop").manifest.raw)
    replace_at_path(raw, path, value)

    with pytest.raises(IntegrityError):
        Manifest.parse(raw)
    with pytest.raises(ValidationError):
        validate_schema_instance("manifest-v1.schema.json", raw)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(("trust", "level"), "upstream-pinned", id="non-quarantined-trust"),
        pytest.param(("trust", "limitations"), [], id="missing-quarantine-limitation"),
        pytest.param(("verification", "status"), "passed", id="passing-quarantine"),
    ],
)
def test_non_runnable_manifest_schema_matches_parser_rejections(
    path: tuple[str | int, ...], value: object
) -> None:
    raw = copy.deepcopy(Catalogue().get("bwapp").manifest.raw)
    replace_at_path(raw, path, value)

    with pytest.raises(IntegrityError):
        Manifest.parse(raw)
    with pytest.raises(ValidationError):
        validate_schema_instance("manifest-v1.schema.json", raw)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(("trust_evidence",), [], id="missing-trust-evidence"),
        pytest.param(
            ("trust_evidence",),
            ["http://example.test/evidence"],
            id="non-https-trust-evidence",
        ),
        pytest.param(("verified_at",), "2026-09-06T17:36:29+02:00", id="non-canonical-timestamp"),
        pytest.param(("verified_at",), "2026-02-30T15:36:29Z", id="invalid-timestamp"),
        pytest.param(("verified_platforms",), ["linux/s390x"], id="unsupported-verified-platform"),
        pytest.param(
            ("verified_platforms",),
            ["linux/amd64", "linux/amd64"],
            id="duplicate-verified-platform",
        ),
        pytest.param(("sbom_url",), "http://example.test/sbom", id="non-https-evidence-url"),
    ],
)
def test_lock_schema_matches_parser_rejections(path: tuple[str | int, ...], value: object) -> None:
    raw = copy.deepcopy(Catalogue().get("juice-shop").lock.raw)
    replace_at_path(raw, path, value)

    with pytest.raises(IntegrityError):
        Lockfile.parse(raw)
    with pytest.raises(ValidationError):
        validate_schema_instance("lock-v1.schema.json", raw)


@pytest.mark.parametrize("status", ["permitted", "prohibited"])
def test_lock_schema_requires_evidence_for_resolved_redistribution(status: str) -> None:
    raw = copy.deepcopy(Catalogue().get("juice-shop").lock.raw)
    raw["redistribution_status"] = status
    raw["redistribution_evidence_url"] = ""

    with pytest.raises(IntegrityError):
        Lockfile.parse(raw)
    with pytest.raises(ValidationError):
        validate_schema_instance("lock-v1.schema.json", raw)


def test_schema_files_are_canonical_json() -> None:
    root = Path("src/vulndockyard/data/schemas")
    for path in sorted(root.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        assert path.read_text(encoding="utf-8") == json.dumps(value, indent=2) + "\n"

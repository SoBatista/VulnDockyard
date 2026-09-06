from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

from vulndockyard.catalogue import Catalogue
from vulndockyard.models import LOCK_KEYS, MANIFEST_KEYS


def schema(name: str) -> dict[str, Any]:
    path = resources.files("vulndockyard").joinpath("data", "schemas", name)
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


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


def test_schema_files_are_canonical_json() -> None:
    root = Path("src/vulndockyard/data/schemas")
    for path in sorted(root.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        assert path.read_text(encoding="utf-8") == json.dumps(value, indent=2) + "\n"

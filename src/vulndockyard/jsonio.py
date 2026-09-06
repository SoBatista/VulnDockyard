"""Strict JSON decoding shared by trusted-state boundaries."""

from __future__ import annotations

import json
from typing import Any


class StrictJSONError(ValueError):
    """JSON used duplicate keys or non-standard numeric constants."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise StrictJSONError(f"non-standard JSON numeric constant: {value}")


def strict_json_loads(value: str | bytes) -> Any:
    return json.loads(
        value,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )

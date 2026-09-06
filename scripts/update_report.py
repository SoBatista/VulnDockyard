#!/usr/bin/env python3
"""Generate a read-only candidate report; never activate or publish updates."""

from __future__ import annotations

import dataclasses
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from vulndockyard import __version__
from vulndockyard.catalogue import Catalogue
from vulndockyard.errors import VulnDockyardError
from vulndockyard.updates import check_latest


def report() -> dict[str, object]:
    results: list[dict[str, object]] = []
    for lab in Catalogue().all():
        if lab.manifest.adapter_status.value != "runnable":
            continue
        try:
            item = dataclasses.asdict(check_latest(lab))
            item["result"] = "candidate" if item["update_available"] else "current"
        except VulnDockyardError as exc:
            item = {
                "lab_id": lab.manifest.id,
                "result": "discovery-error",
                "reason": str(exc),
                "activation": "none",
            }
        results.append(item)
    return {
        "schema_version": 1,
        "controller_version": __version__,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "read_only": True,
        "candidates": results,
        "notice": "Discovery does not change a reviewed manifest or production lock.",
    }


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if len(values) != 1:
        print("Usage: update_report.py OUTPUT.json", file=sys.stderr)
        return 2
    output = Path(values[0])
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.write_text(json.dumps(report(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

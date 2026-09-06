#!/usr/bin/env python3
"""Run release-gate Docker checks through the controller's local-socket policy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from vulndockyard.docker import Docker  # noqa: E402
from vulndockyard.errors import VulnDockyardError  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Use VulnDockyard's validated local Docker socket for a release gate."
    )
    parser.add_argument("gate", choices=("preflight", "audit"))
    args = parser.parse_args(argv)
    docker = Docker()
    try:
        if args.gate == "preflight":
            print(json.dumps(docker.preflight(), sort_keys=True, separators=(",", ":")))
            return 0
        residual = docker.managed_resources()
    except VulnDockyardError as exc:
        print(f"Docker {args.gate} failed: {exc}", file=sys.stderr)
        return int(exc.exit_code)
    if any(residual.values()):
        print(
            "Residual VulnDockyard resources detected: "
            + json.dumps(residual, sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
        return 1
    print("No managed containers, networks, or volumes remain.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Minimal privileged entry point for an atomic /etc/hosts update."""

from __future__ import annotations

import os
import re
import sys

from .hosts import HostsManager

HOSTNAME = re.compile(r"^[a-z][a-z0-9-]{0,61}\.test$")


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if len(values) != 2 or values[0] not in {"add", "remove"} or not HOSTNAME.fullmatch(values[1]):
        print("Usage: python -m vulndockyard.hosts_helper {add|remove} LAB.test", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("Error: this narrow helper must run as root", file=sys.stderr)
        return 1
    HostsManager().apply(values[1], add=values[0] == "add")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

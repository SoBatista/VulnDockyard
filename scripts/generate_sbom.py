#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 JSON SBOM for a built wheel."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path


def _identifier(value: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", value)


def generate(wheel: Path, output: Path) -> None:
    wheel_sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            raise RuntimeError("wheel must contain exactly one METADATA file")
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        name = str(metadata["Name"])
        version = str(metadata["Version"])
        files = []
        relationships = []
        for member in sorted(archive.namelist()):
            if member.endswith("/"):
                continue
            identifier = _identifier(member)
            digest = hashlib.sha256(archive.read(member)).hexdigest()
            files.append(
                {
                    "SPDXID": identifier,
                    "fileName": member,
                    "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                }
            )
            relationships.append(
                {
                    "spdxElementId": "SPDXRef-Package",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": identifier,
                }
            )
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-{version}-wheel",
        "documentNamespace": f"https://github.com/SoBatista/VulnDockyard/sbom/{wheel_sha}",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: VulnDockyard-generate-sbom/1"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "checksums": [{"algorithm": "SHA256", "checksumValue": wheel_sha}],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{name}@{version}",
                    }
                ],
            }
        ],
        "files": files,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package",
            },
            *relationships,
        ],
    }
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if len(values) != 2:
        print("Usage: generate_sbom.py WHEEL OUTPUT.spdx.json", file=sys.stderr)
        return 2
    try:
        generate(Path(values[0]), Path(values[1]))
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        print(f"SBOM generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

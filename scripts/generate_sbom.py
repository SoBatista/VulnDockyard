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

from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

REQUIREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[A-Za-z0-9._,-]+)\])?"
    r"\s*==\s*(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)"
    r"(?:\s*;\s*(?P<marker>.+))?\s*$"
)


def _identifier(value: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", value)


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def validate_spdx(path: Path) -> None:
    """Parse and validate an SPDX 2.x document with the official SPDX tool."""
    try:
        document = parse_file(str(path))
        messages = validate_full_spdx_document(document)
    except Exception as exc:  # SPDX exposes several format-specific parser exceptions.
        raise RuntimeError(f"official SPDX validation could not parse the document: {exc}") from exc
    if messages:
        detail = "; ".join(message.validation_message for message in messages)
        raise RuntimeError(f"official SPDX validation rejected the document: {detail}")


def _runtime_dependencies(metadata: object) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    get_all = getattr(metadata, "get_all", None)
    requirements = get_all("Requires-Dist", []) if callable(get_all) else []
    packages: list[dict[str, object]] = []
    relationships: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw_requirement in sorted(str(value) for value in requirements):
        match = REQUIREMENT.fullmatch(raw_requirement)
        if match is None:
            raise RuntimeError(
                "runtime dependency must use an exact == version for deterministic SBOM output: "
                f"{raw_requirement}"
            )
        marker = match.group("marker") or ""
        if re.search(r"\bextra\b", marker):
            continue
        name = match.group("name")
        normalized = _normalized_name(name)
        version = match.group("version")
        key = (normalized, version)
        if key in seen:
            continue
        seen.add(key)
        identifier = _identifier(f"Dependency-{normalized}-{version}")
        package: dict[str, object] = {
            "SPDXID": identifier,
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/{normalized}@{version}",
                }
            ],
        }
        qualifiers = []
        if match.group("extras"):
            qualifiers.append(f"extras={match.group('extras')}")
        if marker:
            qualifiers.append(f"marker={marker}")
        if qualifiers:
            package["comment"] = "Runtime requirement qualifiers: " + "; ".join(qualifiers)
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": identifier,
            }
        )
    return packages, relationships


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
        file_sha1s = []
        for member in sorted(archive.namelist()):
            if member.endswith("/"):
                continue
            identifier = _identifier(member)
            content = archive.read(member)
            digest = hashlib.sha256(content).hexdigest()
            sha1 = hashlib.sha1(content, usedforsecurity=False).hexdigest()
            file_sha1s.append(sha1)
            files.append(
                {
                    "SPDXID": identifier,
                    "fileName": member,
                    "licenseConcluded": "NOASSERTION",
                    "licenseInfoInFiles": ["NOASSERTION"],
                    "copyrightText": "NOASSERTION",
                    "checksums": [
                        {"algorithm": "SHA1", "checksumValue": sha1},
                        {"algorithm": "SHA256", "checksumValue": digest},
                    ],
                }
            )
            relationships.append(
                {
                    "spdxElementId": "SPDXRef-Package",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": identifier,
                }
            )
    dependency_packages, dependency_relationships = _runtime_dependencies(metadata)
    verification_code = hashlib.sha1(
        "".join(sorted(file_sha1s)).encode("ascii"), usedforsecurity=False
    ).hexdigest()
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
                "packageVerificationCode": {"packageVerificationCodeValue": verification_code},
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "primaryPackagePurpose": "APPLICATION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": wheel_sha}],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{name}@{version}",
                    }
                ],
            },
            *dependency_packages,
        ],
        "files": files,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package",
            },
            *dependency_relationships,
            *relationships,
        ],
    }
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validate_spdx(output)


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

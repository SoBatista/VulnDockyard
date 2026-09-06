# Release and repository operations

`src/vulndockyard/_version.py` is authoritative. `VERSION`, package metadata,
CLI output, README, and changelog are checked projections. Releases use SemVer,
Keep a Changelog, reviewed PR version state, and exactly one release-impact label.

Before publication, run `scripts/self-test.sh` from a clean committed tree. It
uses bounded per-phase and overall watchdogs and writes
`artifacts/checkpoint.json`. Locally applicable required gates cannot be skipped;
remote-only gates remain explicitly recorded as unverified skips until their
documented bootstrap point. The suite compares two builds, installs from a
tracked-files-only release shape into a clean venv,
generates an SPDX package SBOM with explicit `DEPENDS_ON` relationships for exact
runtime requirements, runs the real digest-pinned adapter smoke, and audits
residual Docker resources. Build, CI, and verification environments install the
complete dependency closure from `requirements-dev.lock` with pip hash checking,
then install the local project or wheel with dependency resolution disabled. The
lock is a checked projection of `uv.lock`; both versions and every accepted
artifact SHA-256 must match.

The bootstrap gate also clones the committed local repository into a private
temporary directory with no hardlinks, follows the documented hash-locked
development installation, and invokes both CLI entry points from that isolated
checkout. This verifies fresh-clone instructions without contacting or mutating
the GitHub repository.

The release workflow is manual-only and must be dispatched from `main` after the
maintainer explicitly approves publication. It accepts a CI run ID, verifies via
the GitHub API that the run named `CI` succeeded for the identical `main` commit,
refuses a non-stable or inconsistent version, refuses to move an existing tag,
creates an annotated immutable `vX.Y.Z` tag, and idempotently creates the GitHub
Release with notes extracted from the reviewed changelog. It never runs from
development branches or pull-request code. Release building occurs in a separate
read-only job. Only its short-lived, checksummed payload crosses into the protected
publication job; that job installs no dependencies, performs no build, attests the
payload, and invokes only the standard-library publication path. The publisher
requires the exact expected artifact set and rejects malformed, duplicate,
escaping, missing, extra, or mismatched checksum entries. A separate manual
workflow downloads and verifies the actual published wheel, SBOM, checksums, tag,
release notes, and source archive. An existing release is idempotent only when its
tag, title, body, draft/prerelease flags, assets, and asset bytes match the reviewed
release exactly. Post-release verification checks every asset attestation,
reconstructs the deterministic source archive from the annotated tag, regenerates
the SBOM from the published wheel, and performs a hash-locked clean installation.

Recommended solo-maintainer ruleset:

- Pull request, required checks, resolved conversations, and linear history.
- Block force pushes and branch/tag deletion.
- Zero mandatory approvals until a second trusted reviewer exists.
- Narrow administrator/release-automation bypass only.
- Require signed commits on `main` only after confirming the actual workflow can
  satisfy it without routine bypasses.
- Enable private vulnerability reporting, secret scanning, push protection,
  Dependabot alerts, and dependency graph.

Observe check names on the first pull request before configuring required status
contexts; do not invent them from YAML job names. Create labels `release:major`,
`release:minor`, and `release:patch`. No repository variable is required for the
controller-only release. A future public GHCR build uses the protected `release`
environment only after its manifest records redistribution authority.

Remote-only bootstrap gates are the first hosted CI/CodeQL/dependency-review run,
repository ruleset behavior, private reporting/settings, GitHub artifact
attestations, GHCR keyless signing, and post-publication download verification.

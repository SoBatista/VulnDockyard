# Release and repository operations

`src/vulndockyard/_version.py` is authoritative. `VERSION`, package metadata,
CLI output, README, and changelog are checked projections. Releases use SemVer,
Keep a Changelog, reviewed PR version state, and exactly one release-impact label.

Before publication, run `scripts/self-test.sh` from a clean committed tree. It
uses bounded per-phase and overall watchdogs and writes
`artifacts/checkpoint.json`. Required skips are failures. The suite compares two
builds, installs from a tracked-files-only release shape into a clean venv,
generates an SPDX package SBOM, runs the real digest-pinned adapter smoke, and
audits residual Docker resources.

The release workflow is triggered only by successful CI on `main`, refuses a
non-stable or inconsistent version, refuses to move an existing tag, creates an
annotated immutable `vX.Y.Z` tag, and idempotently creates the GitHub Release with
notes extracted from the reviewed changelog. It never runs from development
branches or pull-request code. A separate manual workflow downloads and verifies
the actual published wheel, SBOM, checksums, tag, and source archive.

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


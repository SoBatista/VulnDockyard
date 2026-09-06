# Release and repository operations

Version 1.0.0 is the target first release and has not been released. While its
gates remain incomplete, the README identifies it as an unreleased target and
its notes remain under `[Unreleased]` in the changelog. The final reviewed
release change must move those notes to one dated `[1.0.0]` section, change the
README projection to a released version, and pass every release gate. No tag,
GitHub Release, package, or image may be published from the target state.

`src/vulndockyard/_version.py` is authoritative. `VERSION`, package metadata,
CLI output, README, and changelog are checked projections. Releases use SemVer,
Keep a Changelog, reviewed PR version state, and exactly one release-impact label.
The pull-request metadata job also checks every commit in the exact base-to-head
range for a DCO sign-off matching its author identity.

Before publication, run `scripts/self-test.sh` from a clean committed tree. It
uses bounded per-phase and overall watchdogs and writes
`artifacts/checkpoint.json`. Locally applicable required gates cannot be skipped;
remote-only gates remain explicitly recorded as unverified skips until their
documented bootstrap point. In that machine contract, `result` is a backwards-
compatible alias of `local_result`, `result_scope` is
`locally-applicable-gates`, and `release_ready` remains false while any required
local or remote gate appears in `blockers`. A local pass therefore cannot be
mistaken for authorization to publish. The suite compares two builds, installs from a
tracked-files-only release shape into a clean venv,
generates an SPDX package SBOM with explicit `DEPENDS_ON` relationships for exact
runtime requirements and validates it with the pinned official SPDX tool, scans both
the tracked release tree and all reachable Git
history with the checksum-pinned Gitleaks binary, runs the real digest-pinned
adapter smoke, and audits residual Docker resources. Development, build, CI, and
verification environments install the complete dependency
closure from `requirements-dev.lock` with pip hash checking. Clean wheel and
post-publication installation checks instead preinstall only the exact runtime closure
from `requirements-runtime.lock`, then install the wheel with dependency resolution
disabled. Both lockfiles are checked projections of `uv.lock`; versions and every
accepted artifact SHA-256 must match.

The smoke gate discovers the runnable catalogue IDs, requires every collected
Docker smoke test to declare exactly one matching `lab_id` marker, and fails when
any runnable lab is missing, skipped, not run, or unsuccessful. Its deterministic
`artifacts/smoke-report.json` receipt is embedded into the complete checkpoint;
no required skip can be represented as a pass.

The bootstrap gate also clones the committed local repository into a private
temporary directory with no hardlinks, follows the documented hash-locked
development installation, and invokes both CLI entry points from that isolated
checkout. This verifies fresh-clone instructions without contacting or mutating
the GitHub repository.

The always-reported `runnable-adapter-smoke` job classifies each `main` push from
the exact before/after commit range. Changes to controller source, tests, scripts,
dependency locks, package metadata, or the smoke workflow run the complete
runnable-lab matrix. A push limited to reviewed documentation and governance
files reports success without installing dependencies or pulling images. A
missing or malformed commit range fails closed to the full smoke. Manual dispatch
always runs it. Expanding the low-risk set requires a reviewed risk-model change;
new executable or catalogue paths are never implicitly exempted.

The required CI quality job owns the single installed-environment dependency check
through `scripts/ci-check.sh`; the project validator reads installed distribution
metadata directly, so it works in both `uv` environments without bundled `pip` and
standard GitHub Python environments. The complete local gate performs the same
check in its own environment. The Security workflow is reserved for CodeQL so pull
requests do not pay for a duplicate dependency installation and validation job.

The release workflow is manual-only and must be dispatched from `main` after the
maintainer explicitly approves publication. It accepts a CI run ID, verifies via
the GitHub API that `.github/workflows/ci.yml` produced the run named `CI` and
succeeded for the identical `main` commit,
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

Before the first publication, create the `release` GitHub environment explicitly;
do not rely on workflow dispatch to create an unprotected environment implicitly.
Restrict its deployment branches to `main`, configure the maintainer as its required
reviewer where the public-repository GitHub plan supports that protection, prevent
self-review when a second trusted reviewer exists, and grant no environment secrets.
If GitHub requires a paid plan for a required protection, stop and report that remote
bootstrap blocker rather than weakening the publication boundary.

Observe check names on the first pull request before configuring required status
contexts; do not invent them from YAML job names. Create labels `release:major`,
`release:minor`, and `release:patch`. No repository variable is required for the
controller-only release. A future public GHCR build uses the protected `release`
environment only after its manifest records redistribution authority.

Remote pre-release bootstrap gates are the first hosted CI, CodeQL, and pull-request
dependency-review runs plus repository ruleset behavior and private-reporting settings.
GitHub artifact creation and attestation necessarily occur during an explicitly approved
release; genuine published-artifact download and attestation verification are separate
post-release gates. Neither is represented as a prerequisite that must pass before the
artifact exists. GHCR signing remains inapplicable until a redistribution-authorized
project-built image is approved.

## Standalone packaged installation

After a release is published, download its wheel and `SHA256SUMS` from the same
GitHub Release. Keep their original filenames in one empty directory, verify the
wheel before installation, and use a dedicated virtual environment:

```bash
sha256sum --ignore-missing --check SHA256SUMS
python3 -m venv vulndockyard-venv
vulndockyard-venv/bin/python -m pip install ./vulndockyard-1.0.0-py3-none-any.whl
vulndockyard-venv/bin/vulndockyard version
vulndockyard-venv/bin/vdy doctor
```

The checksum file is useful only after its own origin has been authenticated.
Compare it with the checksums shown by the HTTPS GitHub Release, and verify the
GitHub artifact attestation with GitHub CLI when the release provides one:

```bash
gh attestation verify vulndockyard-1.0.0-py3-none-any.whl \
  --repo SoBatista/VulnDockyard
```

The wheel pins its small runtime dependency set, but pip may download those exact
dependencies from the configured package index. For an offline installation,
pre-download wheels for the target Python/platform in a trusted environment and
transfer them with their independently recorded hashes; do not disable checksum
or attestation verification for the VulnDockyard wheel.

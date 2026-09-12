# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Target release: 1.0.0 (not yet released).

### Added

- Provenance-aware Python controller with deterministic human and JSON output.
- Distinct crash-recoverable rebuild, reset, and remove semantics, including
  exact persistent-volume preservation, foreign-consumer rejection, and
  fail-closed persistent-update handling.
- Fail-closed versioned lab manifests, immutable locks, four image-trust levels,
  and twelve officially researched initial catalogue entries.
- Digest-pinned OWASP Juice Shop reference adapter with loopback gateway,
  Docker 28 isolated application networking and exact endpoint topology, a
  read-only root with bounded hardened ephemeral storage, validated seed helper,
  complete rollback-policy and health snapshots, crash-safe transient adoption,
  exact ownership labels, bounded lifecycle, identity readiness, clean reset,
  transactional updates, and safe cleanup.
- Atomic marker-delimited `.test` hosts management that preserves unrelated data.
- Pinned, checksum-verified, XDG-cached Vulhub metadata provider with a
  fail-closed Compose validator and an initially empty reviewed runnable allowlist.
- Unit, policy, packaging, release-shape, fresh-clone installation, and opt-in
  real Docker smoke tests.
- Apache-2.0 OSS governance, security, maintenance, CI, release, SBOM, and
  post-publication verification foundations.

### Fixed

- Run the `/etc/hosts` helper's `sudo` in the caller's session instead of the
  detached subprocess session, so `hosts add` and `hosts remove` can prompt for a
  password (or reuse the terminal's cached credential) rather than failing with
  "a terminal is required to read the password" on every default sudo setup.
- Make the `doctor` Docker Engine upgrade guidance follow the base distribution
  from `/etc/os-release`: LMDE is directed to Docker's Debian repository with its
  `DEBIAN_CODENAME`, Ubuntu-based Mint to the Ubuntu repository with its
  `UBUNTU_CODENAME`, instead of Ubuntu instructions for every Mint edition.
- Align the Juice Shop rebuild smoke with upstream's documented self-healing:
  application state is intentionally ephemeral and its SQLite schema is recreated
  on every process start, while generic persistent-volume behavior remains covered
  by controller policy tests.
- Validate generated SPDX 2.3 SBOMs with the pinned official SPDX tool, keep clean
  installation checks free of development dependencies, and fail final checkpoints
  when any managed Docker resource remains. Checkpoints now distinguish a local pass
  from full release readiness and enumerate every remaining required blocker.
- Enforce one wall-clock deadline for health and metadata HTTP reads, revalidate
  containment before logs, surface Docker log failures, and make JSON destructive
  and hosts-repair previews non-mutating. Destructive confirmations bind an exact
  ownership-validated resource fingerprint and preserve honest persistence status.
  Preview tokens additionally bind the command and exact image-removal scope, human
  previews enumerate every resource and image, and legacy logs fail closed without
  an applicable containment-policy snapshot.
- Restore the complete Contributor Covenant 2.1 text and consolidate installed-
  environment dependency validation into the required quality and local gates.
- Bind confirmed hosts edits to one checksum-verified atomic replacement, serialize
  Vulhub cache readers and writers, surface same-lab Docker orphans to observational
  commands, serialize pulls with lifecycle mutation, bound URL opening, and retain
  captured output when the bounded log-follow window closes.
- Validate packaged catalogue data against executable Draft 2020-12 schemas and keep
  bootstrap release notes byte-for-byte equivalent to their reviewed target section.

[Unreleased]: https://github.com/SoBatista/VulnDockyard/commits/main

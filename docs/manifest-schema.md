# Manifest and lock contract v1

Reviewed manifests are package data under `src/vulndockyard/data/manifests/`.
Immutable locks are separate under `data/locks/`; mutable update discovery and
provider indexes are stored only in XDG cache. The machine schemas are
[`manifest-v1.schema.json`](../src/vulndockyard/data/schemas/manifest-v1.schema.json)
and [`lock-v1.schema.json`](../src/vulndockyard/data/schemas/lock-v1.schema.json).

The controller's strict parser is authoritative. It rejects unknown fields,
non-HTTPS evidence URLs, non-`.test` hostnames, invalid IDs, unsupported backends,
partial commits, malformed ports/dates, trust/status contradictions, service/image
role mismatches, and every missing digest on a runnable adapter. The Draft 2020-12
schemas are executable contracts for editors and external tooling, not just field
inventories: CI validates every packaged manifest and lock with `jsonschema` and a
format checker, and negative parity cases prove that schema-expressible parser
rejections remain rejected by both layers.

The manifest schema enforces runnable commit, tag, trust, evidence, image-role,
architecture, service-protocol, health, initialization, verification, read-only
root, and non-root storage requirements. It also enforces quarantined trust and
blocked verification for both non-runnable statuses. The lock schema enforces
HTTPS trust and optional evidence URLs, non-empty trust evidence, canonical UTC
verification timestamps, supported unique platforms, and a non-empty HTTPS
evidence URL for resolved redistribution decisions. The parser remains necessary
for relationships that portable JSON Schema cannot express without project-
specific extensions:
unique role and service-name properties, a shared service port, cross-list mount
name/path uniqueness and non-overlap, aggregate mount size, exact persistence-to-
mount set equality, and manifest/lock/filename catalogue binding.

`ephemeral_storage` declares every writable mount needed by a read-only
application root. `uid` and `gid` are the non-root numeric identity used by the
application and the ownership applied to its writable data. `seeded` mounts are
initialized from the corresponding directory in the locked application image;
`empty` mounts intentionally begin blank. Every mount is exactly
`{name, container_path, size_mb}`. Names and container paths are unique across
both groups, mount paths must be absolute normalized POSIX paths and may not nest
or overlap, and sizes are bounded to 1–4096 MiB per mount and 8192 MiB in total.
At most 32 mounts may appear in either group. Quarantined adapters retain an
explicit empty contract until their writable paths and ownership are reviewed.

Every writable-storage name is also listed exactly once in
`persistence.volumes`, so lifecycle ownership and cleanup remain auditable.
`persistence.required: false` declares the complete set as disposable scratch:
the backend may discard it during rebuild, and reset and remove always discard
it. `persistence.required: true` declares the complete set as retained
application data: rebuild must preserve it, while reset must discard and
reinitialize only those exactly owned declared volumes. Mixed persistent and
disposable writable paths are not part of manifest v1.

The persistent-volume contract is deliberately narrow. Every runnable adapter
uses non-zero application UID and GID values. A persistent adapter must declare
at least one writable mount, and its
`persistence.volumes` set must exactly equal the names across
`ephemeral_storage.seeded` and `ephemeral_storage.empty`. The Docker backend uses
a transient networkless initializer as UID 0 with only `CAP_CHOWN`; it may write
only the exact owned volumes, recursively applies the declared non-root ownership
without following symlinks, and is removed before the application runs. The
application itself never inherits initializer privilege. Quarantined adapters
may retain incomplete persistence metadata while their runtime layout is researched;
runnable-only constraints do not make that catalogue metadata executable.

Trust levels are `upstream-signed`, `upstream-pinned`, `vulndockyard-built`, and
`quarantined`. Digest pinning is mandatory for runnable images but proves only
immutability. Origin, license, architecture, verification, and limitations are
separate evidence. A non-runnable adapter must be quarantined with a reason.

Locks retain lab/upstream versions, commit, exact image repository/digest/role and
architectures, template/source checksums, build-recipe revision, trust evidence,
verification timestamp, and tested platforms. Structured build evidence records
the SBOM, provenance, signature, and redistribution-review status and URL. A
`vulndockyard-built` lock is runnable only when all four records are present,
redistribution is explicitly `permitted`, the canonical source checksum and build
recipe are locked, and the application image is under the project GHCR namespace.
`upstream-signed` additionally requires immutable provenance and signature URLs.
Tags are discovery evidence only; Docker execution is always
`repository@sha256:...`.

The lock binds version, commit, trust evidence, verification date/platforms, and
every digest already reviewed in a manifest even while an adapter is quarantined.
Unresolved image names may remain searchable in the manifest, but they never
become lock images or executable references without a digest.

For the generic controller backend, `template_sha256` is the canonical SHA-256 of
the manifest fields that drive rendering: backend, images, services, hostname,
health and initialization, lifecycle/reset, resource and persistence policy,
ephemeral writable-storage policy, egress, and dangerous-capability declarations.
The catalogue recomputes it before any runnable adapter can load. Quarantined
adapters may leave it empty because no runtime template is approved.

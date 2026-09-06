# Manifest and lock contract v1

Reviewed manifests are package data under `src/vulndockyard/data/manifests/`.
Immutable locks are separate under `data/locks/`; mutable update discovery and
provider indexes are stored only in XDG cache. The machine schemas are
[`manifest-v1.schema.json`](../src/vulndockyard/data/schemas/manifest-v1.schema.json)
and [`lock-v1.schema.json`](../src/vulndockyard/data/schemas/lock-v1.schema.json).

The controller's strict parser is authoritative. It rejects unknown fields,
non-HTTPS evidence URLs, non-`.test` hostnames, invalid IDs, unsupported backends,
partial commits, malformed ports/dates, trust/status contradictions, service/image
role mismatches, and every missing digest on a runnable adapter. JSON Schema is
provided for editors and external tooling; tests keep its required fields aligned
with the parser.

Trust levels are `upstream-signed`, `upstream-pinned`, `vulndockyard-built`, and
`quarantined`. Digest pinning is mandatory for runnable images but proves only
immutability. Origin, license, architecture, verification, and limitations are
separate evidence. A non-runnable adapter must be quarantined with a reason.

Locks retain lab/upstream versions, commit, exact image repository/digest/role and
architectures, template/source checksums, build-recipe revision, trust evidence,
verification timestamp, and tested platforms. Tags are discovery evidence only;
Docker execution is always `repository@sha256:...`.

For the generic controller backend, `template_sha256` is the canonical SHA-256 of
the manifest fields that drive rendering: backend, images, services, hostname,
health and initialization, lifecycle/reset, resource and persistence policy,
egress, and dangerous-capability declarations. The catalogue recomputes it before
any runnable adapter can load. Quarantined adapters may leave it empty because no
runtime template is approved.

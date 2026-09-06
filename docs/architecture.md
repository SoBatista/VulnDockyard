# Architecture

VulnDockyard is a Python 3.11+ process, not a daemon. `argparse` provides the CLI;
strict dataclasses parse reviewed JSON manifests and immutable locks; a bounded
argv-only subprocess adapter invokes Docker Engine. PyYAML is the single runtime
dependency and is used only for safe parsing of untrusted provider Compose data.

```text
CLI / JSON v1
     |
catalogue + immutable locks ---- update discovery (read-only)
     |                                  |
trust and policy checks          reviewed candidate only
     |
runtime ownership state (XDG, 0600)
     |
Docker Engine argv adapter
     |
per-run internal app network --- app (unpublished, no egress)
     |                         |
     +--- fixed-target Caddy gateway --- per-run ingress network
                                           |
                                     127.0.0.1:80 only
```

Before any pull or operation that can execute a runnable lab, the Docker Engine
server version is parsed and required to be at least 28.0.0. The local Linux
machine architecture is normalized to an explicit OCI platform and checked
against every required locked image and the lock's reviewed smoke-test platforms.
Advertising an architecture in image metadata is not treated as functional
verification. Unknown versions, operating systems, architectures, or unverified
platforms fail closed. Recovery operations that only stop or clean exact owned
resources remain available on an older Engine.

The gateway's separate ingress network is intentional. On Docker Engine, marking
the gateway ingress network `--internal` makes its published loopback mapping
unreachable. The vulnerable application remains solely on its internal network
and therefore has no egress. The narrowly constrained gateway joins that network
and a non-internal ingress network, accepts loopback traffic, and can reach only
the fixed `app:PORT` upstream configured by controller-owned argv. It runs
read-only as UID/GID 1000 with `no-new-privileges`, `cap_drop=ALL`, and one
reviewed gateway-only exception for `NET_BIND_SERVICE`. The high listener port
does not need this capability, but the locked official Caddy binary carries the
corresponding file capability and Docker cannot execute it when that capability
is absent from the bounding set. Its writable tmpfs mounts are owned by UID/GID 1000.

The application bridge is created with both `--internal` and Docker's
`com.docker.network.bridge.gateway_mode_ipv4=isolated` driver option. Immediately
after each network creation, the controller inspects the exact returned object
ID and requires the bridge driver, expected `Internal` flag, complete ownership
identity, safe local/non-attachable/non-ingress/IPv4-only flags, and an exact
gateway-mode option set. The ingress bridge explicitly requests ordinary `nat`
mode and rejects routed, unprotected, or trusted-interface options. A policy
mismatch is removed only after ownership validation; an
ownership mismatch is left untouched and reported.

This network boundary assumes Docker 28's default daemon port filtering remains
enabled. Docker's effective `allow-direct-routing` startup state is not fully
available through its Engine API; deliberately weakening daemon routing or host
firewall policy is an administrator action outside the controller's trust boundary.

Every resource records ownership, lab ID, manifest identity/version, run ID,
creation time, trust state, and role. Names aid operators but confer no ownership.
Any mismatch stops cleanup. State is checkpointed after each creation so an
interrupted start can recover exact object IDs. Run-state schema v3 also snapshots
the complete effective resource, egress, writable-storage, and bounded
health/identity contract. This lets an update revalidate and smoke its preserved
rollback deployment even after the installed manifest advances; a legacy state
without that snapshot is not a transactional rollback base.

Application, gateway, and seeder containers use Docker's bounded local logging
driver (two compressed 10 MiB files) and set the swap-inclusive memory ceiling
equal to the memory limit, preventing a lab from gaining an unbounded host-log
or swap budget.
The application root is read-only. Each reviewed writable path is either a
bounded direct tmpfs or an owned `noexec,nosuid,nodev` local-driver tmpfs
volume. Seeded volumes are populated by a short-lived, network-disabled,
same-image helper running a fixed controller-owned Node script; its inspected
effective policy, exact null-network attachment, liveness, and readiness marker
are required, and no seeder remains in the steady state. The application must be
observed running before the seeder is removed. The controller re-seeds volatile
data after a stop, while reset/remove delete only the selected run's exactly owned
storage. If interruption occurs in the narrow create/checkpoint window,
observational commands report the orphan; explicit start or cleanup adopts it
only by deterministic name and complete ownership identity before validation or
removal.

Every steady-state lifecycle inspection revalidates the effective image, user,
fixed command, namespaces, capabilities, devices, resource/log limits, mounts,
the complete set of container network attachments, and the complete set of
running network endpoints before reporting a healthy managed state. Docker omits
stopped containers from network endpoint inventories, so their configured
attachments remain enforced through container inspection.

An update candidate is never synthesized from mutable discovery data. It is the
already-installed, schema-validated manifest/lock pair, and it is eligible only
when preserved runtime state has a different manifest identity. The controller
holds its lifecycle lock, retains the prior deployment intact, and smokes the
candidate through a controller-selected temporary loopback port. Only after that
passes does it replace the two gateway containers to transfer the original port,
then repeats readiness and identity checks. A strict fsynced update journal records
each phase and exact resource IDs. Failure removes the candidate and recreates the
prior gateway from its bounded state snapshot with the prior running/stopped roles;
a restarted prior application is re-seeded and must pass its snapshot health and
identity checks before the journal is deleted. Transient rollback seeders are
checkpointed in the update journal and also adopted by deterministic name plus
complete ownership and effective-policy validation across the create/checkpoint
crash window. A later execution-capable lifecycle command safely completes or
rolls back an interrupted phase. `stop`, `remove`, and `purge` use a cleanup-only
recovery path that never creates or starts a container, including on an older
Engine.
Observational commands refuse a pending journal; only an explicit execution
lifecycle command may recreate, reseed, or start a rollback deployment.

The controller itself remains unprivileged. Optional friendly-hostname changes
are delegated to a small isolated standard-library helper installed at a fixed
root-owned path. The caller validates its owner, mode, parent directories, inode,
and release checksum before invoking it through the system `sudo` binary.

Provider snapshots live under the XDG cache. The checkout stores only their
pinned commit/checksum and reviewed allowlist. Downloaded Compose is parsed and
reported, never executed; a future runnable provider entry must render a separate
controller-owned sanitized deployment.

# Threat model

## Assets and adversaries

Assets are the host, Docker daemon, unrelated containers/data, local network,
credentials, and users who may mistake a training target for safe software.
Adversarial input includes manifests, provider archives, YAML, image contents,
HTTP responses, existing Docker objects, filenames, and upstream metadata.
An intentionally vulnerable application may be fully compromised by a local
visitor; containment must assume that outcome.

## Trust boundaries and controls

- Reviewed repository data fails closed on unknown or missing fields.
- Runnable images require immutable digests and separate publisher evidence.
- Arbitrary images are explicitly untrusted even when digest-pinned.
- The application is unpublished, has no automatic restart, receives finite
  memory/CPU/PID limits, drops capabilities, and is denied a default route. Its
  Docker 28+ internal bridge additionally uses isolated IPv4 gateway mode.
- Every newly created bridge is inspected by returned object ID for the expected
  driver, internal flag, exact driver options, and full ownership identity before
  any container is attached.
- Effective container image, user, command, namespaces, capabilities, devices,
  resource/log limits, writable mounts, and exact network attachments are
  revalidated against the reviewed runtime contract during lifecycle inspection.
- Managed networks reject foreign endpoints, and managed containers reject every
  additional network attachment. Cleanup-only interruption recovery never starts
  or creates a lab on an unsupported Engine.
- Status, logs, open, and verification never perform execution-capable update
  recovery. A rollback that restarts an application first restores its declared
  volatile seed data and verifies the prior snapshot's identity. Transient
  rollback seeders are journaled or adopted across every create/checkpoint window.
- Only the constrained gateway publishes, and only on `127.0.0.1`.
- No host network, privileged mode, runtime socket, devices, host PID/IPC/user
  namespace, broad bind mounts, or uncontrolled builds are permitted.
- Subprocesses use argument vectors, no shell, bounded timeouts, and bounded
  output. Health checks verify identity and expected functionality markers.
- Cleanup requires exact state IDs plus every ownership label. No global prune or
  prefix-only deletion exists.
- Hosts editing uses an exact block, no-follow descriptor reads, regular-file/owner/mode
  and inode checks, a same-directory temporary, validation, atomic replacement, and
  preservation of unrelated bytes. An inode change before replacement aborts the edit.
  Elevation executes only a fixed root-owned, non-writable, checksum-matched helper;
  user-writable virtual-environment and project Python code never runs as root.
- Provider downloads require pinned commit and archive checksum; extraction rejects
  traversal, links, devices, duplicates, and resource bombs. Provider cache roots and
  metadata must remain current-user-owned, private, regular non-symlink paths.

## Residual risk

Docker is not a security boundary equal to a disposable VM. Kernel/container
escape exercises and definitions requesting dangerous namespaces or devices are
blocked and require a future dedicated disposable-VM backend. A gateway could be
attacked by malformed application responses. Docker caches vulnerable layers.
Loopback services remain reachable by other local users/processes. Browser state
can outlive server reset. Users must not add real credentials to labs.

The local Docker daemon and its administrator are trusted. In particular, the
daemon must retain Docker 28's default port-filtering behavior; an administrator
can deliberately weaken it with `allow-direct-routing` or host firewall changes.
The Engine API does not expose every effective daemon startup flag, so the
controller cannot prove that an administrator has not disabled those filters.

Out of scope: protecting a hostile host administrator, making the training apps
production-safe, preventing every local browser-origin interaction, or claiming
publisher identity from a digest alone.

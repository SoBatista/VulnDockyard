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
  memory/CPU/PID limits, drops capabilities, and is denied a default route.
- Only the constrained gateway publishes, and only on `127.0.0.1`.
- No host network, privileged mode, runtime socket, devices, host PID/IPC/user
  namespace, broad bind mounts, or uncontrolled builds are permitted.
- Subprocesses use argument vectors, no shell, bounded timeouts, and bounded
  output. Health checks verify identity and expected functionality markers.
- Cleanup requires exact state IDs plus every ownership label. No global prune or
  prefix-only deletion exists.
- Hosts editing uses an exact block, regular-file/owner/mode checks, a same-directory
  temporary, validation, atomic replacement, and preservation of unrelated bytes.
- Provider downloads require pinned commit and archive checksum; extraction rejects
  traversal, links, devices, duplicates, and resource bombs.

## Residual risk

Docker is not a security boundary equal to a disposable VM. Kernel/container
escape exercises and definitions requesting dangerous namespaces or devices are
blocked and require a future dedicated disposable-VM backend. A gateway could be
attacked by malformed application responses. Docker caches vulnerable layers.
Loopback services remain reachable by other local users/processes. Browser state
can outlive server reset. Users must not add real credentials to labs.

Out of scope: protecting a hostile host administrator, making the training apps
production-safe, preventing every local browser-origin interaction, or claiming
publisher identity from a digest alone.


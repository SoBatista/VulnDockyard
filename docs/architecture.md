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

The gateway's separate ingress network is intentional. On Docker Engine, a
container attached only to an `--internal` network does not receive a usable
published-port mapping. The vulnerable application remains solely on the internal
network. The gateway joins both networks, accepts loopback traffic, and can reach
only the fixed `app:PORT` upstream configured by controller-owned argv. It runs
read-only with `no-new-privileges`, `cap_drop=ALL`, and only
`NET_BIND_SERVICE`, required by the official Caddy binary's file capability.

Every resource records ownership, lab ID, manifest identity/version, run ID,
creation time, trust state, and role. Names aid operators but confer no ownership.
Any mismatch stops cleanup. State is checkpointed after each creation so an
interrupted start can recover exact object IDs.

Provider snapshots live under the XDG cache. The checkout stores only their
pinned commit/checksum and reviewed allowlist. Downloaded Compose is parsed and
reported, never executed; a future runnable provider entry must render a separate
controller-owned sanitized deployment.


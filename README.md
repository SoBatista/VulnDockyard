# VulnDockyard

[![Target version](https://img.shields.io/badge/target--version-1.0.0-orange)](CHANGELOG.md)

> **Danger:** VulnDockyard runs intentionally vulnerable software. Use it only
> on a local system you control. The controller binds its gateway to loopback,
> isolates each run, and denies container egress by default; those controls do
> not make a vulnerable application safe for shared or production systems.

A provenance-aware local runner for intentionally vulnerable security labs.

Target version: `1.0.0` (unreleased; release gates incomplete).

## Quick start

Requires Python 3.11+ and Docker Engine 28.0.0 or newer. The minimum Engine
version is a containment requirement for isolated bridge gateway mode, not only
a compatibility preference. Docker Compose v2 is required only for reviewed
multi-container adapters and provider development.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
vulndockyard doctor
vulndockyard list
vulndockyard trust juice-shop
vulndockyard pull juice-shop
vulndockyard up juice-shop
vulndockyard hosts helper
# Inspect and checksum the displayed helper, then install it once with:
sudo /usr/bin/install -o root -g root -m 0755 DISPLAYED_HELPER \
  /usr/local/libexec/vulndockyard-hosts
vulndockyard hosts add juice-shop --yes
vulndockyard open juice-shop
vulndockyard reset juice-shop --yes
vulndockyard remove juice-shop --yes
```

Port 80 is deliberate: the reviewed gateway publishes only
`127.0.0.1:80`, so the friendly URL is `http://juice-shop.test` while the
application remains unpublished on its internal Docker network. If port 80 is
busy, choose a fallback explicitly with `--port`; VulnDockyard never silently
changes the interface or port.

Never run a virtual-environment or editable-install Python entry point with
`sudo`. Hosts changes cross a deliberately narrow privilege boundary: the CLI
will invoke only a root-owned, non-writable helper whose exact SHA-256 matches
this controller version. `vulndockyard hosts helper` reports the packaged source,
required checksum, and fixed installation location for inspection.

After `v1.0.0` is published, a standalone release install will use the release
wheel and checksum described in [release verification](docs/release.md). Until
then, use the development installation above; no public package or release is
being claimed by this tree.

Docker necessarily caches pulled image layers in Docker's own storage. `remove`
keeps those layers. `purge LAB --images --yes` removes only the exact reviewed
image digests known to that adapter, after ownership-scoped runtime cleanup. It
never invokes global Docker, image, or volume pruning.

## Safety and trust

Only adapters marked `runnable` can start. Every runnable image is referenced by
an immutable OCI digest and has separately documented publisher-origin evidence.
Digest pinning proves immutability, not publisher identity. An arbitrary image
can be used only with the conspicuous unsafe-development flags and never
inherits catalogue trust.

The Apache-2.0 [LICENSE](LICENSE) covers VulnDockyard controller code only. Each
integrated lab retains its own upstream license; see `vulndockyard info LAB` and
[the catalogue review](docs/catalogue.md). No vulnerable application source tree
is stored here.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md),
[commands](docs/commands.md), and [development](CONTRIBUTING.md).

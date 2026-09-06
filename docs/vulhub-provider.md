# Vulhub provider

The provider pins official `vulhub/vulhub` commit
`aeaf65793f147f29bd50841ef77f4e9cad07ecc7` and its independently calculated
archive SHA-256. `provider sync vulhub` downloads into an XDG cache, verifies the
archive, rejects unsafe tar members, parses `environments.toml` and Compose, then
writes a separately checksummed deterministic index.

All entries are searchable by upstream path, CVE, product, and category. The v1
runnable allowlist is intentionally empty. Neither a `vulhub/*` name nor Vulhub's
MIT repository license proves the affected product's publisher, license,
architecture, compatibility, or container safety.

Validation rejects privileged mode, host networking/PID/IPC/user namespace,
devices, runtime sockets and host binds, unknown extensions/keys, interpolation,
uncontrolled builds, unreviewed commands/entrypoints, capabilities beyond the
small allowlist, missing limits, non-loopback publication, and unverified or
mutable images. Known kernel/container-escape exercises remain searchable but
require a future disposable-VM backend. Downloaded Compose is never executed.

A future allowlist record must pin provider commit/path, Compose checksum, exact
images, origins, licenses, architectures, commands, capability exceptions, expected
functionality, and dated smoke evidence. Runtime uses a rendered project-owned
template, never the cached source definition.


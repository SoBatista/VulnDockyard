# Command reference

Global `--json` emits deterministic contract version 1 and may appear before or
after a command. `--ground-truth` opts into non-solution verification metadata;
normal output excludes spoilers and flags. Stable exits are: 0 success, 2 usage,
3 not found/ambiguous, 4 policy refusal, 5 preflight, 6 runtime, 7 integrity, and
8 cancelled/interrupted.

| Command | Behavior |
|---|---|
| `help [COMMAND]` | Root or focused help. |
| `version` | Canonical controller version. |
| `doctor` | Python, parsed Engine version/isolation capability, Compose, loopback port, hosts, and XDG diagnostics. |
| `list` / `search QUERY` | Reviewed catalogue search; optional synced Vulhub search. |
| `info LAB` / `trust LAB` | Contract details and provenance limits. |
| `pull LAB` | Pull only reviewed `name@sha256` references. |
| `up LAB` / `start LAB` | Idempotent start; default gateway is `127.0.0.1:80`. |
| `status [LAB]` | Requested reference, resolved digest, trust, run ID, and lock match. |
| `verify LAB` | Identity and expected-functionality readiness plus lock match. |
| `open LAB` / `logs LAB` | Open URL or show bounded application logs. |
| `down LAB` / `stop LAB` | Idempotently stop, retain runtime and data. |
| `restart LAB` | Stop/start the same locked deployment. |
| `rebuild LAB` | Recreate only the same reviewed lock/reference; refuse stale or untrusted state. |
| `reset LAB --yes` | Preview, then return owned data to the declared clean state. |
| `remove LAB --yes` | Remove owned runtime resources; retain images. |
| `purge LAB --images --yes` | Remove owned state and optionally exact known digests. |
| `update --check [LAB]` | Read-only stable release discovery. |
| `update [LAB]` | Transactionally activate an installed reviewed candidate; refuse discovery-only versions. |
| `hosts add/remove [LAB]` | Preview and atomically edit only the managed block through the verified helper. |
| `hosts helper` | Show the packaged helper path, release checksum, fixed target, owner, and mode. |
| `provider sync/status vulhub` | Verify/cache or report pinned official metadata. |
| `completion SHELL` | Bash, Zsh, or Fish completion source. |

`--port PORT` is an explicit fallback and stays loopback-only. `--allow-multiple`
acknowledges additional resource use and wider local attack surface. A lab that
declares Internet egress requires `--acknowledge-egress`. An alternate application
image requires both `--unsafe-development` and an immutable `--unsafe-image`; the
run is visibly untrusted and cannot match the reviewed lock.

After an interactive non-JSON `up`, the CLI offers to add the selected `.test`
name when it is absent. Declining, interrupting, or failing this optional hosts
step leaves the successfully started lab running and reports the manual command.

Docker operations are always bounded. Advanced users may configure validated
seconds with `VDY_TIMEOUT_PULL`, `VDY_TIMEOUT_START`, `VDY_TIMEOUT_HEALTH`,
`VDY_TIMEOUT_STOP`, `VDY_TIMEOUT_CLEANUP`, and `VDY_TIMEOUT_INSPECT`. Each variable
has a finite accepted range; invalid, zero, negative, or unbounded values fail the
preflight. Readiness uses Python's built-in bounded HTTP client, so no external
`curl` or `wget` executable is required. Its effective deadline is the lower of
`VDY_TIMEOUT_HEALTH` and the reviewed manifest timeout. `pull`, `up`, and update
activation also fail before pulling when any required image omits the validated
local `linux/amd64`, `linux/arm64`, or `linux/arm/v7` platform. The same operations
also require that exact local platform in the reviewed lock's smoke-test evidence;
an advertised but unverified architecture is not runnable.

Runnable lab execution requires Docker Engine 28.0.0 or newer so the internal
application bridge can use isolated IPv4 gateway mode. `pull`, `up`, `update`,
`restart`, `rebuild`, `reset`, and `verify` fail closed on an older or malformed
server version. `stop`/`down`, `remove`, `purge`, and the residual-resource audit
remain available for exact owned-resource recovery.

This minimum prevents the isolated application bridge from receiving a default
outbound route; it is a containment boundary, not a general compatibility floor.
On Linux Mint, identify the Ubuntu base release for the installed Mint version,
then follow Docker's official Ubuntu Engine installation instructions to upgrade
manually to Engine 28.0.0 or newer. Rerun `vulndockyard doctor` afterward.
VulnDockyard never installs, upgrades, or modifies Docker automatically.

`/etc/hosts` is the only privileged operation. Install the helper reported by
`hosts helper` as `/usr/local/libexec/vulndockyard-hosts`, owned by `root:root`
and mode `0755`. The CLI rejects a symlink, a writable helper or parent directory,
and any checksum mismatch. It never executes the active virtual environment or
project package as root. Fixture and unit-test paths are transformed in-process
without elevation.

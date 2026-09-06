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
| `open LAB` / `logs LAB` | Open URL or show bounded application logs after revalidating the effective containment policy. |
| `down LAB` / `stop LAB` | Idempotently stop, retain runtime and data. |
| `restart LAB` | Stop/start the same locked deployment. |
| `rebuild LAB` | Recreate only the same reviewed lock/reference; preserve every exactly owned declared persistent volume, and refuse stale, untrusted, missing, relabeled, or foreign-consumed state. |
| `reset LAB --yes` | Preview exact declared and currently present owned volume names, delete only owned data, then create the declared clean state. |
| `remove LAB --yes` | Preview and remove exact owned runtime resources; retain images. |
| `purge LAB --images --yes` | Preview owned state and optionally exact known digests before removal. |
| `update --check [LAB]` | Read-only stable release discovery. |
| `update LAB` | Transactionally activate one installed reviewed candidate; refuse discovery-only versions and a missing LAB. |
| `hosts add/remove [LAB]` | Preview and atomically edit only the managed block through the verified helper. |
| `hosts helper` | Show the packaged helper path, release checksum, fixed target, owner, and mode. |
| `provider sync/status vulhub` | Verify/cache or report pinned official metadata. |
| `completion SHELL` | Bash, Zsh, or Fish completion source. |

Manifest v1 supports a binary writable-storage lifecycle: all declared mounts are
either disposable or persistent. No packaged runnable adapter currently requires
persistence, but the controller lifecycle is implemented and policy-tested.
Persistent updates remain blocked until an adapter supplies a reviewed data
migration and rollback contract.

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
preflight. Readiness and metadata retrieval use a size-bounded streaming reader
under one caller-visible wall-clock deadline, so no external
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
remain available for exact owned-resource recovery. If an update was interrupted,
these cleanup commands resolve its journal without creating or starting containers.
Observational `status`, `logs`, `open`, and `verify` commands never recover a
pending update; they fail with explicit execution-recovery and cleanup-recovery
choices instead of unexpectedly starting a vulnerable lab.

For `--json reset|remove|purge`, omitting `--yes` returns one deterministic,
non-mutating preview document. A second invocation with `--yes` performs the
operation. Pass its `preview_token` back with `--preview-token` to require an
exact match. The token binds the command, the exact owned Docker resources, and
the exact immutable image references requested by `purge --images`; a token for
`remove` or a non-image purge cannot authorize a broader operation. Every mutation
also binds the immediately computed resource preview and refuses if owned state
changes before the lifecycle lock is reacquired. Human confirmation lists every
present resource and every image reference in scope.
An unknown persistence classification is reported as JSON `null`, never as a false
claim. `--json doctor --repair-hosts` follows the same preview rule and never
mixes prompts or human text into the JSON stream.

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

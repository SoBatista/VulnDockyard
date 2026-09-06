# Update and reproducibility pipeline

`update --check` performs bounded read-only discovery against a canonical GitHub
release endpoint and reports SemVer changes. It does not pull, edit locks, rebuild,
or activate. Proxy use and redirects are disabled, and the destination is derived
only from a reviewed canonical GitHub repository. A tag never becomes an execution
reference.

The review pipeline is deliberately separated:

1. Discover upstream change.
2. Review source/image origin and license.
3. Generate a candidate immutable lock.
4. Build locally if redistribution permits.
5. Smoke identity and expected training functionality.
6. Review and approve the candidate.
7. Publish a project image only from the protected release workflow.
8. Activate only after readiness and identity; roll back on any failure.

The transactional primitive stages and smokes before activation, keeps the prior
known-good deployment recoverable, and rolls back/discards a failing candidate.
The installed manifest and lock are a candidate only when their reviewed manifest
identity differs from preserved runtime state. `update` pulls only those locked
digests and starts the candidate on a controller-selected temporary loopback port
while the prior deployment and its original port remain intact. After temporary
readiness, application identity, inspected application/gateway image identity,
trust, and lock identity pass, it removes the temporary candidate gateway, removes
the prior gateway, creates the candidate gateway on the original port, and repeats
the checks. Only then does an atomic state replacement activate it and exact-ID
cleanup discard the prior deployment.

Activation preserves the prior lifecycle state: a stopped deployment is started
only long enough to smoke the candidate and remains stopped after activation. On
rollback, only the exact application and gateway roles that were running before
the attempt are restarted. `restart` and `rebuild` refuse a preserved runtime
whose manifest identity differs from the installed lock and direct the operator
to `update`; `rebuild` additionally refuses to replace an untrusted or otherwise
different image reference because it cannot reproduce that runtime safely.

The state snapshot records the prior digest-pinned gateway reference and upstream
port. A strict, bounded, atomically replaced update journal records the prior and
candidate states, temporary port, lifecycle roles, and cutover phase. If candidate
startup or either identity verification fails, candidate resources are removed by
exact ownership labels and IDs and the prior gateway is recreated when cutover had
already removed it. On a later lifecycle command, an interrupted pre-activation
phase rolls back; a journaled ready candidate completes activation and prior
cleanup. Unknown or ambiguous resources still stop recovery safely.

A discovery result is never an execution candidate. When upstream reports a newer
version but the installed package contains no corresponding reviewed manifest/lock,
`update` refuses and preserves the existing deployment. With no active runtime it
reports `no-runtime`; matching installed/runtime identities report
`already-current`. Scheduled automation reports candidates only; it never changes
or publishes a production lock.

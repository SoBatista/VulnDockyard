# Update and reproducibility pipeline

`update --check` performs bounded read-only discovery against a canonical GitHub
release endpoint and reports SemVer changes. It does not pull, edit locks, rebuild,
or activate. A tag never becomes an execution reference.

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
The current lock remains available until a reviewed package release replaces it.
Scheduled automation reports candidates only; it never changes or publishes a
production lock.


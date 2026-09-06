# Contributing

Contributions are welcome for the controller, reviewed adapter metadata, tests,
documentation, and workflows. Never add a vulnerable application's source tree.

## Development

```bash
git clone https://github.com/SoBatista/VulnDockyard.git
cd VulnDockyard
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
pre-commit install
scripts/self-test.sh
```

`requirements-dev.lock` is the pip-consumable, fully hashed projection of
`uv.lock`, including the runtime, build, test, and release closure. Refresh both
only in a dependency-review change with `uv lock`, then
`uv export --frozen --extra dev --no-emit-project --format requirements.txt
--no-header`. Repository checks reject missing packages, version drift, and any
artifact hash that differs between the two locks.

Do not run `.venv/bin/vulndockyard`, an editable install, or project Python code
with `sudo`. Use the reviewed standalone helper contract described by
`vulndockyard hosts helper` when manually testing real `/etc/hosts` integration.

The complete self-test runs real digest-pinned Docker smoke tests and requires an
available loopback port. Use focused unit commands while iterating; do not mark a
release ready until every locally applicable required phase passes. The checkpoint
keeps remote-only release gates as explicit unverified skips until their documented
bootstrap point.

## Changes and release impact

Use focused Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`,
`chore:`). Every post-1.0 pull request carries exactly one of
`release:major`, `release:minor`, or `release:patch`, and includes that exact
single SemVer increment plus its reviewed changelog section. Version state is
reviewed in the pull request; no post-merge bump commit is created.

All commits must include a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Use `git commit -s`. By signing off, you certify the [DCO](DCO.md). Do not submit
secrets, proprietary source, exploit walkthroughs, or registry credentials.
The pull-request metadata check evaluates every commit between the live base and
the reviewed head and requires a sign-off matching that commit's author name and
email; a sign-off in only the final commit is insufficient.

## Adapter changes

Provide canonical upstream evidence, a full OCI digest, publisher-origin evidence,
license/redistribution review, architectures, containment review, expected
functionality tests, reset semantics, and a dated platform verification. Pulling
an image or receiving HTTP 200 is not sufficient. Changes to intentional vulnerable
behavior require explicit review so a training exercise is not accidentally fixed.

PRs require passing checks, resolved conversations, linear history, and maintainer
approval to merge. The project never automerges.

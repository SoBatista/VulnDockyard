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
`uv.lock`, including the runtime, build, test, and release closure.
`requirements-runtime.lock` contains only the runtime closure used by clean wheel
verification. Refresh all three only in a dependency-review change with `uv lock`, then
`uv export --frozen --extra dev --no-emit-project --format requirements.txt
--no-header --output-file requirements-dev.lock` and
`uv export --frozen --no-dev --no-emit-project --format requirements.txt
--no-header --output-file requirements-runtime.lock`. Repository checks reject
missing packages, version drift, and artifact hashes that differ between the locks.

Do not run `.venv/bin/vulndockyard`, an editable install, or project Python code
with `sudo`. Use the reviewed standalone helper contract described by
`vulndockyard hosts helper` when manually testing real `/etc/hosts` integration.

The complete self-test runs real digest-pinned Docker smoke tests and requires an
available loopback port. Use focused unit commands while iterating; do not mark a
release ready until every locally applicable required phase passes. The checkpoint
keeps remote-only release gates as explicit unverified skips until their documented
bootstrap point.

The test gate enforces 85% branch-aware controller coverage. The only configured
line exclusions are type-checking-only branches and direct `__main__` launch
guards, because neither contains application behavior; production error paths and
security-policy decisions are not excluded.

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
email in its terminal trailer block; a sign-off in only the final commit is
insufficient. The workflow checks out the exact PR head so GitHub's synthetic
merge commit never enters that range.

## Adapter changes

Provide canonical upstream evidence, a full OCI digest, publisher-origin evidence,
license/redistribution review, architectures, containment review, expected
functionality tests, reset semantics, and a dated platform verification. Pulling
an image or receiving HTTP 200 is not sufficient. Changes to intentional vulnerable
behavior require explicit review so a training exercise is not accidentally fixed.

PRs require passing checks, resolved conversations, linear history, and maintainer
approval to merge. The project never automerges.

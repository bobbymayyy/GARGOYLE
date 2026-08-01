# Contributing

## Before opening a pull request

```bash
cargo generate-lockfile
make check
```

Commit `Cargo.lock` whenever the resolved graph changes. Release automation rejects an unlocked repository.

Changes to collectors must include:

- hostile-input handling
- a bounded read or collection limit
- parser tests
- privilege/capability impact
- event-schema impact
- threat-model updates when the trust boundary changes

Do not add shell execution, remote command features, or project-owned unsafe Rust without an architecture decision record and explicit security review.

## Commit scope

Prefer small commits that separate:

- event contract changes
- collector behavior
- packaging/hardening
- dependency changes

Dependency additions require a reason, feature review, license review, and confirmation that the function cannot be implemented safely with the standard library at reasonable cost.

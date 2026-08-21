# Security Policy

## Supported versions

Until the first stable release, only the latest tagged version receives security fixes.

## Dependency integrity

GARGOYLE treats `Cargo.lock` as part of the reviewed source state. Normal builds, tests, linting, and container builds use `--locked` so dependency resolution cannot silently drift from the committed graph.

Dependency policy is enforced with `cargo-deny`: yanked crates, wildcard dependencies, unknown registries, and unknown Git sources are denied. Known malicious packages from the August 2026 Rust supply-chain incident are explicitly blocked, including `arrayref` 0.3.10, `append-only-vec` 0.1.9, `proc-macro1`, and `proc-macro-en`.

Changes to `Cargo.toml` that alter dependency resolution should include the corresponding reviewed `Cargo.lock` update. Treat unexpected lockfile changes, new build scripts, new registries, and new Git dependencies as security-sensitive changes.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories for the repository. Include:

- affected version or commit
- deployment mode
- reproduction steps
- impact
- suggested mitigation, when known

Do not include live credentials, private host data, or exploit demonstrations against systems you do not own.

## Response goals

The project will acknowledge a valid report, reproduce it, assess severity, and prepare a coordinated fix before public disclosure. Exact timing depends on complexity and downstream coordination.

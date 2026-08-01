# Validation Status

This v0.2 source tree was assembled on 2026-07-31 in an environment without an installed Rust toolchain, PowerShell runtime, or direct package-network access.

## Completed in the assembly environment

- parsed every TOML, JSON, and YAML file
- checked the JSON Schema as Draft 2020-12
- validated representative process-fingerprint, socket-owner, authentication, and group-membership events against `gargoyle.event/v2`
- checked Bash syntax and executable bits
- structurally checked standalone and embedded PowerShell programs, including balanced delimiters, strings, here-strings, and continuation hygiene
- structurally checked all Rust source, integration-test, and fuzz-target files with a comment/string-aware delimiter scanner
- parsed the AppArmor profile
- verified the systemd unit using a temporary executable stub at its configured path
- checked local Markdown links, repository version consistency, whitespace, and included-file paths
- confirmed all external GitHub Actions references are immutable 40-character commit SHAs
- scanned for project-owned unsafe blocks, unfinished macros, shell command construction, unbounded `Command::output`, silent descriptor truncation, unfinished-work markers, credentials, private-key material, and build debris
- generated and verified the repository manifest and release-archive checksums

The static pass covered 25 Rust files, six embedded PowerShell collector programs, all standalone PowerShell deployment scripts, and four representative v2 events.

## Not claimed

The assembly environment could not execute:

- `cargo fmt`, `cargo clippy`, `cargo test`, `cargo doc`, or either platform build
- Windows CIM, NetTCPIP, Authenticode, Security Event Log, Scheduled Tasks, or PowerShell smoke tests
- Linux runtime collector and smoke tests

No `Cargo.lock`, compiled binary, successful Cargo result, or successful Windows runtime result is fabricated by this source bundle.

## Required trusted-build gate

Generate and review the lockfile first, then commit it before any release tag.

Linux:

```bash
rustup toolchain install 1.97.1 --profile minimal --component clippy,rustfmt
cargo generate-lockfile
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo build --release --locked
./scripts/smoke-test.sh ./target/release/gargoyle
```

Windows:

```powershell
rustup toolchain install 1.97.1 --profile minimal --component clippy,rustfmt
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release --locked
.\scripts\smoke-test.ps1 -Binary .\target\release\gargoyle.exe
```

Run the Windows collector on a disposable test host with the desired audit categories enabled. Exercise process creation, logon success and failure, explicit credentials, privileged logon, local account changes, privileged-group membership changes, listener creation, Security-log clearing, and clean shutdown before promoting the build.

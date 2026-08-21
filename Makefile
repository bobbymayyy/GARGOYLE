SHELL := /bin/bash

.PHONY: build release fmt lint test doc audit deny machete coverage check smoke benchmark clean

build:
	cargo build --locked

release:
	cargo build --release --locked

fmt:
	cargo fmt --all --check

lint:
	cargo clippy --locked --all-targets --all-features -- -D warnings

test:
	cargo test --locked --all-features

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features

audit:
	cargo audit

deny:
	cargo deny check

machete:
	cargo machete

coverage:
	cargo llvm-cov --all-features --workspace --fail-under-lines 35 --lcov --output-path coverage/lcov.info

check: fmt lint test doc

smoke: release
	./scripts/smoke-test.sh ./target/release/gargoyle

benchmark: release
	./scripts/benchmark.sh ./target/release/gargoyle

clean:
	cargo clean
	rm -rf coverage dist

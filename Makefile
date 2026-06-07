# Makefile for Rust project using Cargo

.PHONY: all build check run test bench fuzz clippy clippy-fix fmt doc update

all: fmt clippy-fix

# Build the project with all features enabled in release mode
build:
	cargo build --workspace --release --all-features

# Check the project for compilation errors without producing binaries
check:
	cargo check --workspace --all-features

# Update dependencies to their latest compatible versions
update:
	cargo update

# Run the project with all features enabled in release mode
run:
	cargo run --release --all-features

# Run all tests with all features enabled
test:
	cargo test --workspace --all-features

# Run benchmarks with all features enabled
bench:
	cargo bench --all-features

# Run Clippy linter with nightly toolchain (check only, for CI)
# Uses workspace lints from Cargo.toml
clippy:
	cargo +nightly clippy --workspace \
		--all-targets \
		--all-features \
		-- -D warnings

# Run Clippy linter with auto-fix (for development)
clippy-fix:
	cargo +nightly clippy --workspace \
		--fix \
		--all-targets \
		--all-features \
		--allow-dirty \
		--allow-staged \
		-- -D warnings

# Format the code using rustfmt with nightly toolchain
fmt:
	cargo +nightly fmt

# Generate documentation for all crates and open it in the browser
doc:
	cargo +nightly doc --all-features --no-deps --open

# Smoke-run every libFuzzer target in crates/nula-fuzz (needs the nightly
# toolchain + `cargo install cargo-fuzz`). Override the per-target budget
# with `make fuzz FUZZ_SECS=60`. CI can call this for a short regression
# pass; long campaigns run locally or on a dedicated runner.
FUZZ_SECS ?= 10
fuzz:
	@cargo +nightly fuzz list --fuzz-dir crates/nula-fuzz | while read target; do \
		echo "==> fuzzing $$target for $(FUZZ_SECS)s"; \
		cargo +nightly fuzz run --fuzz-dir crates/nula-fuzz "$$target" -- -max_total_time=$(FUZZ_SECS) || exit 1; \
	done

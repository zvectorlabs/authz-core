# authz-core dev Makefile

.PHONY: help fmt fmt-check check clippy test ci publish install-hooks

help:
	@echo "authz-core commands"
	@echo "  make install-hooks - Install git hooks from .githooks/"
	@echo "  make fmt           - Format code"
	@echo "  make fmt-check     - Check format (CI)"
	@echo "  make check         - cargo check"
	@echo "  make clippy        - Run clippy"
	@echo "  make test          - Run all tests"
	@echo "  make ci            - fmt-check + check + test + clippy"
	@echo "  make publish       - Publish to crates.io (dry-run first)"

install-hooks:
	@echo "Installing git hooks from .githooks/ ..."
	@cp .githooks/pre-commit  .git/hooks/pre-commit
	@cp .githooks/commit-msg  .git/hooks/commit-msg
	@chmod +x .git/hooks/pre-commit .git/hooks/commit-msg
	@echo "Done. Hooks installed: pre-commit, commit-msg"

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

check:
	cargo check

clippy:
	cargo clippy -- -D warnings

test:
	cargo test

ci: fmt-check check test clippy

publish-dry:
	cargo publish --dry-run

publish:
	cargo publish

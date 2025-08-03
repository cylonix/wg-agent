.PHONY: generate build test test-unit test-integration test-ignored clean check-env install-lld test-verbose test-coverage lint fmt fmt-check audit dev-setup watch-test rebuild all dev ci-test help
.DEFAULT_GOAL := build

# Environment check target - now fails on critical issues
check-env:
	@echo "Checking build environment..."
	@which cargo > /dev/null || (echo "Error: cargo not found. Please install Rust toolchain." && exit 1)
	@which cc > /dev/null || (echo "Error: C compiler not found. Please install build-essential." && exit 1)
	@echo "Environment check completed."

# Separate LLD check that can fail or warn based on context
check-lld-required:
	@echo "Checking for LLD linker (required)..."
	@which lld > /dev/null || (echo "Error: LLD linker not found. Run 'make install-lld' to install it." && exit 1)
	@echo "LLD linker found."

check-lld-optional:
	@if command -v lld > /dev/null; then \
		echo "LLD linker found - will use for faster builds"; \
	else \
		echo "Warning: LLD linker not found. Using default linker (slower builds)"; \
		echo "Consider running 'make install-lld' for faster builds"; \
	fi

# Install LLD linker for faster builds
install-lld:
	@echo "Installing LLD linker..."
	@if command -v apt-get > /dev/null; then \
		echo "Detected Debian/Ubuntu system"; \
		sudo apt-get update && sudo apt-get install -y lld; \
	elif command -v dnf > /dev/null; then \
		echo "Detected Fedora system"; \
		sudo dnf install -y lld; \
	elif command -v yum > /dev/null; then \
		echo "Detected CentOS/RHEL system"; \
		sudo yum install -y lld; \
	elif command -v pacman > /dev/null; then \
		echo "Detected Arch Linux system"; \
		sudo pacman -S lld; \
	else \
		echo "Unknown package manager. Please install LLD manually."; \
		echo "For Debian/Ubuntu: sudo apt-get install lld"; \
		echo "For Fedora: sudo dnf install lld"; \
		echo "For CentOS/RHEL: sudo yum install lld"; \
		exit 1; \
	fi
	@echo "LLD installation completed."

generate:
	@echo "Generate wg-agent API"
	git submodule update --init --recursive
	docker pull cylonix/openapi-generator-cli:v7.8.5
	scripts/generate_api.sh

build: check-env check-lld-optional
	@echo "build wg-agent"
	@if command -v lld > /dev/null; then \
		echo "Using LLD for faster linking..."; \
		cd wg-mgr-rs && RUSTFLAGS="-C link-arg=-fuse-ld=lld" cargo build --release; \
	else \
		echo "Using default linker..."; \
		cd wg-mgr-rs && cargo build --release; \
	fi

# Test targets with environment checking - now properly handle missing dependencies
test: check-env
	@echo "Run tests for wg-agent"
	@echo "Checking for any problematic linker configuration..."
	@if [ -f "wg-mgr-rs/.cargo/config.toml" ] && grep -q "fuse-ld=lld" "wg-mgr-rs/.cargo/config.toml" 2>/dev/null; then \
		if ! command -v lld > /dev/null; then \
			echo "Error: .cargo/config.toml specifies LLD linker but LLD is not installed."; \
			echo "Either run 'make install-lld' or remove .cargo/config.toml"; \
			exit 1; \
		fi; \
	fi
	@if command -v lld > /dev/null; then \
		echo "Using LLD for faster test compilation..."; \
		cd wg-mgr-rs && RUSTFLAGS="-C link-arg=-fuse-ld=lld" RUST_LOG=debug RUST_BACKTRACE=1 cargo test; \
	else \
		echo "Using default linker for tests..."; \
		cd wg-mgr-rs && RUST_LOG=debug RUST_BACKTRACE=1 cargo test; \
	fi

test-unit: check-env
	@echo "Run unit tests only"
	@if [ -f "wg-mgr-rs/.cargo/config.toml" ] && grep -q "fuse-ld=lld" "wg-mgr-rs/.cargo/config.toml" 2>/dev/null; then \
		if ! command -v lld > /dev/null; then \
			echo "Error: .cargo/config.toml specifies LLD linker but LLD is not installed."; \
			echo "Either run 'make install-lld' or remove .cargo/config.toml"; \
			exit 1; \
		fi; \
	fi
	@if command -v lld > /dev/null; then \
		cd wg-mgr-rs && RUSTFLAGS="-C link-arg=-fuse-ld=lld" RUST_LOG=debug RUST_BACKTRACE=1 cargo test --lib; \
	else \
		cd wg-mgr-rs && RUST_LOG=debug RUST_BACKTRACE=1 cargo test --lib; \
	fi

test-integration: check-env
	@echo "Run integration tests"
	@if [ -f "wg-mgr-rs/.cargo/config.toml" ] && grep -q "fuse-ld=lld" "wg-mgr-rs/.cargo/config.toml" 2>/dev/null; then \
		if ! command -v lld > /dev/null; then \
			echo "Error: .cargo/config.toml specifies LLD linker but LLD is not installed."; \
			echo "Either run 'make install-lld' or remove .cargo/config.toml"; \
			exit 1; \
		fi; \
	fi
	@if command -v lld > /dev/null; then \
		cd wg-mgr-rs && RUSTFLAGS="-C link-arg=-fuse-ld=lld" RUST_LOG=debug RUST_BACKTRACE=1 cargo test --tests; \
	else \
		cd wg-mgr-rs && RUST_LOG=debug RUST_BACKTRACE=1 cargo test --tests; \
	fi

test-ignored: check-env
	@echo "Run ignored tests (requires root/external services)"
	@echo "Note: This will prompt for sudo password"
	@if [ -f "wg-mgr-rs/.cargo/config.toml" ] && grep -q "fuse-ld=lld" "wg-mgr-rs/.cargo/config.toml" 2>/dev/null; then \
		if ! command -v lld > /dev/null; then \
			echo "Error: .cargo/config.toml specifies LLD linker but LLD is not installed."; \
			echo "Either run 'make install-lld' or remove .cargo/config.toml"; \
			exit 1; \
		fi; \
	fi
	@if command -v lld > /dev/null; then \
		cd wg-mgr-rs && RUSTFLAGS="-C link-arg=-fuse-ld=lld" RUST_LOG=debug RUST_BACKTRACE=1 sudo -E cargo test -- --ignored; \
	else \
		cd wg-mgr-rs && RUST_LOG=debug RUST_BACKTRACE=1 sudo -E cargo test -- --ignored; \
	fi

test-verbose: check-env
	@echo "Run tests with verbose output"
	@if [ -f "wg-mgr-rs/.cargo/config.toml" ] && grep -q "fuse-ld=lld" "wg-mgr-rs/.cargo/config.toml" 2>/dev/null; then \
		if ! command -v lld > /dev/null; then \
			echo "Error: .cargo/config.toml specifies LLD linker but LLD is not installed."; \
			echo "Either run 'make install-lld' or remove .cargo/config.toml"; \
			exit 1; \
		fi; \
	fi
	@if command -v lld > /dev/null; then \
		cd wg-mgr-rs && RUSTFLAGS="-C link-arg=-fuse-ld=lld" RUST_LOG=debug RUST_BACKTRACE=1 cargo test -- --nocapture; \
	else \
		cd wg-mgr-rs && RUST_LOG=debug RUST_BACKTRACE=1 cargo test -- --nocapture; \
	fi

test-coverage: check-env
	@echo "Run tests with coverage (requires cargo-tarpaulin)"
	@which cargo-tarpaulin > /dev/null || (echo "Installing cargo-tarpaulin..." && cargo install cargo-tarpaulin)
	@if [ -f "wg-mgr-rs/.cargo/config.toml" ] && grep -q "fuse-ld=lld" "wg-mgr-rs/.cargo/config.toml" 2>/dev/null; then \
		if ! command -v lld > /dev/null; then \
			echo "Error: .cargo/config.toml specifies LLD linker but LLD is not installed."; \
			echo "Either run 'make install-lld' or remove .cargo/config.toml"; \
			exit 1; \
		fi; \
	fi
	@if command -v lld > /dev/null; then \
		cd wg-mgr-rs && RUSTFLAGS="-C link-arg=-fuse-ld=lld" RUST_LOG=debug RUST_BACKTRACE=1 cargo tarpaulin --out Html; \
	else \
		cd wg-mgr-rs && RUST_LOG=debug RUST_BACKTRACE=1 cargo tarpaulin --out Html; \
	fi

lint: check-env
	@echo "Run clippy linting"
	cd wg-mgr-rs && cargo clippy -- -D warnings

fmt:
	@echo "Format code"
	cd wg-mgr-rs && cargo fmt

fmt-check:
	@echo "Check code formatting"
	cd wg-mgr-rs && cargo fmt --check

clean:
	@echo "Clean build artifacts"
	cd wg-mgr-rs && cargo clean

check:
	@echo "Check code without building"
	cd wg-mgr-rs && cargo check

# Install all development dependencies
dev-setup: install-lld
	@echo "Install development dependencies"
	cd wg-mgr-rs && cargo install cargo-tarpaulin cargo-watch cargo-audit
	@echo "Development setup completed."

watch-test: check-env
	@echo "Watch for changes and run tests"
	@which cargo-watch > /dev/null || (echo "Installing cargo-watch..." && cargo install cargo-watch)
	@if [ -f "wg-mgr-rs/.cargo/config.toml" ] && grep -q "fuse-ld=lld" "wg-mgr-rs/.cargo/config.toml" 2>/dev/null; then \
		if ! command -v lld > /dev/null; then \
			echo "Error: .cargo/config.toml specifies LLD linker but LLD is not installed."; \
			echo "Either run 'make install-lld' or remove .cargo/config.toml"; \
			exit 1; \
		fi; \
	fi
	@if command -v lld > /dev/null; then \
		cd wg-mgr-rs && RUSTFLAGS="-C link-arg=-fuse-ld=lld" RUST_LOG=debug RUST_BACKTRACE=1 cargo watch -x test; \
	else \
		cd wg-mgr-rs && RUST_LOG=debug RUST_BACKTRACE=1 cargo watch -x test; \
	fi

# Security audit
audit: check-env
	@echo "Running security audit"
	@which cargo-audit > /dev/null || (echo "Installing cargo-audit..." && cargo install cargo-audit)
	cd wg-mgr-rs && cargo audit

# Targets that require LLD
build-fast: check-env check-lld-required
	@echo "Fast build with LLD (LLD required)"
	cd wg-mgr-rs && RUSTFLAGS="-C link-arg=-fuse-ld=lld" cargo build --release

test-fast: check-env check-lld-required
	@echo "Fast tests with LLD (LLD required)"
	cd wg-mgr-rs && RUSTFLAGS="-C link-arg=-fuse-ld=lld" RUST_LOG=debug RUST_BACKTRACE=1 cargo test

# Utility targets
fix-cargo-config:
	@echo "Removing problematic .cargo/config.toml if it exists..."
	@if [ -f "wg-mgr-rs/.cargo/config.toml" ]; then \
		echo "Backing up existing config to .cargo/config.toml.bak"; \
		mv wg-mgr-rs/.cargo/config.toml wg-mgr-rs/.cargo/config.toml.bak; \
		echo "Removed .cargo/config.toml"; \
	else \
		echo "No .cargo/config.toml found"; \
	fi

# Full development workflow
all: fmt lint test build

# Development cycle with fast feedback
dev: fmt lint test-unit

# CI/CD pipeline targets
ci-test: check-env fmt-check lint test

# Clean and rebuild from scratch
rebuild: clean build

# Show help
help:
	@echo "Available targets:"
	@echo "  check-env       - Check build environment and dependencies"
	@echo "  install-lld     - Install LLD linker for faster builds"
	@echo "  build          - Build release binary (with optional LLD)"
	@echo "  build-fast     - Build release binary (requires LLD)"
	@echo "  test           - Run all tests (with optional LLD)"
	@echo "  test-fast      - Run all tests (requires LLD)"
	@echo "  test-unit      - Run unit tests only"
	@echo "  test-integration - Run integration tests"
	@echo "  test-ignored   - Run ignored tests (requires root)"
	@echo "  test-verbose   - Run tests with verbose output"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  lint           - Run clippy linting"
	@echo "  fmt            - Format code"
	@echo "  fmt-check      - Check code formatting"
	@echo "  audit          - Run security audit"
	@echo "  dev-setup      - Install all development dependencies"
	@echo "  watch-test     - Watch for changes and run tests"
	@echo "  fix-cargo-config - Remove problematic .cargo/config.toml"
	@echo "  clean          - Clean build artifacts"
	@echo "  rebuild        - Clean and rebuild from scratch"
	@echo "  all            - Run full workflow (fmt, lint, test, build)"
	@echo "  dev            - Quick development cycle (fmt, lint, unit tests)"
	@echo "  ci-test        - CI/CD pipeline tests"
	@echo "  help           - Show this help message"
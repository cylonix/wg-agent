.PHONY: generate build
.DEFAULT_GOAL := build

generate:
	@echo "Generate wg-agent API"
	git submodule update --init --recursive
	docker pull cylonix/openapi-generator-cli:v7.8.5
	scripts/generate_api.sh

build:
	@echo "build wg-agent"
	cd wg-mgr-rs && cargo build --release

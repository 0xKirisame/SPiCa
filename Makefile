# SPiCa Makefile
# Run `make install-deps` and `make install-tools` once, then `make all` to build,
# `make run` to detect, `make install` to integrate with initramfs.

.PHONY: help install-deps install-tools generate-vmlinux build-ebpf build all run \
        install uninstall check check-ebpf test clean

# Default target
help:
	@echo "SPiCa — build targets:"
	@echo ""
	@echo "  Setup (one-time):"
	@echo "    install-deps       Install system dependencies (requires root)"
	@echo "    install-tools     Install bpf-linker and aya-tool"
	@echo "    generate-vmlinux  Generate BTF bindings (run once per kernel update)"
	@echo ""
	@echo "  Build:"
	@echo "    build-ebpf        Compile the eBPF probe (dev/check only)"
	@echo "    build             Compile everything: generates key, compiles eBPF + userspace"
	@echo "    all               Full pipeline: generate-vmlinux → build"
	@echo ""
	@echo "  Run:"
	@echo "    run               Run SPiCa (requires root)"
	@echo "    install           Install to /usr/local/bin + initramfs integration (root)"
	@echo "    uninstall         Remove SPiCa + initramfs integration (root)"
	@echo ""
	@echo "  Verify:"
	@echo "    check             cargo check for all userspace crates"
	@echo "    check-ebpf        cargo check for the eBPF crate (bpfel-unknown-none)"
	@echo "    test              Run unit tests for Mac-testable crates"
	@echo ""
	@echo "  Cleanup:"
	@echo "    clean             Remove build artifacts"
	@echo ""
	@echo "  Typical setup:"
	@echo "    make install-deps"
	@echo "    make install-tools"
	@echo "    make all"
	@echo "    make run          # or: make install (for early-boot protection)"

install-deps:
	@if command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S --needed --noconfirm base-devel clang llvm libelf bpf tpm2-tss ima-evm-utils; \
	elif command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && sudo apt-get install -y build-essential clang llvm libelf-dev \
			linux-tools-common bpftool libtss2-dev tpm2-tools ima-evm-utils; \
	elif command -v dnf >/dev/null 2>&1; then \
		sudo dnf install -y clang llvm elfutils-libelf-devel bpftool \
			tpm2-tss-devel tpm2-tools ima-evm-utils; \
	else \
		echo "Unsupported package manager. Install manually:"; \
		echo "  clang, llvm, libelf, bpftool, tpm2-tss (dev headers), ima-evm-utils"; \
		exit 1; \
	fi
	rustup toolchain install nightly --component rust-src
	rustup override set nightly

install-tools:
	cargo install bpf-linker
	cargo install --git https://github.com/aya-rs/aya aya-tool

generate-vmlinux:
	cargo run --package xtask generate-vmlinux

build-ebpf:
	cargo run --package xtask build-ebpf --release

build:
	cargo build --release

all: generate-vmlinux build

run:
	sudo ./target/release/spica

install:
	sudo ./target/release/spica install

uninstall:
	sudo ./target/release/spica uninstall

check:
	cargo check --workspace --exclude spica-ebpf

check-ebpf:
	cargo check --manifest-path spica-ebpf/Cargo.toml \
	            --target bpfel-unknown-none \
	            -Z build-std=core

test:
	cargo test -p spica-common -p spica-detect -p spica-key -p spica-seccheck -p spica-install

clean:
	cargo clean

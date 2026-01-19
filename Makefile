CARGO := cargo
RUSTUP := rustup
XTASK := $(RUSTUP) run nightly $(CARGO) run --package xtask
TARGET_DIR := target/release
BINARY := spica

.PHONY: all setup build build-ebpf build-user run clean check test help

all: build

setup:
	@echo "Setting up Nightly Toolchain..."
	$(RUSTUP) toolchain install nightly
	$(RUSTUP) override set nightly

build-ebpf:
	@echo "Building eBPF Kernel Probe..."
	$(XTASK) build-ebpf --release

build-user: build-ebpf
	@echo "Building Userspace Agent..."
	$(CARGO) build --release --package spica

build: build-user
	@echo "Build Complete: $(TARGET_DIR)/$(BINARY)"

run: build
	@echo "Launching SPiCa..."
	sudo $(TARGET_DIR)/$(BINARY)

dev: build-ebpf
	@echo "Running in Dev Mode..."
	$(CARGO) run --package spica

check:
	$(CARGO) check
	$(XTASK) build-ebpf --release --check

clean:
	@echo "Cleaning up..."
	$(CARGO) clean

test:
	$(CARGO) test

help:
	@echo "Available commands:"
	@echo "  make setup      - Install Nightly Rust and set directory override"
	@echo "  make build      - Build everything (eBPF + Userspace Release)"
	@echo "  make run        - Build and run SPiCa (requires sudo)"
	@echo "  make dev        - Build and run in debug mode"
	@echo "  make clean      - Remove build artifacts"
	@echo "  make check      - Run cargo check"

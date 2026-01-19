CARGO := cargo
XTASK := $(CARGO) +nightly run --package xtask
TARGET_DIR := target/release
BINARY := spica

.PHONY: all build build-ebpf build-user run clean check test help

all: build

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
	@echo "  make build"
	@echo "  make run"
	@echo "  make dev"
	@echo "  make clean"
	@echo "  make check"

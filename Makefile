# SPiCa Makefile
# Mac: edit code here, push, then run on Linux target.
# Linux: run `make install-tools` once, then `make all` to build, `make run` to detect.

.PHONY: help install-tools generate-vmlinux build-ebpf build all run clean

# Default target
help:
	@echo "SPiCa — build targets:"
	@echo ""
	@echo "  install-tools      Install bpf-linker and aya-tool (Linux, run once)"
	@echo "  generate-vmlinux   Generate BTF bindings for running kernel (Linux, run once per kernel update)"
	@echo "  build-ebpf         Compile the eBPF kernel probe (Linux)"
	@echo "  build              Compile the userspace engine"
	@echo "  all                Full pipeline: generate-vmlinux → build-ebpf → build (Linux)"
	@echo "  run                Run SPiCa (Linux, requires root)"
	@echo "  clean              Remove build artifacts"
	@echo ""
	@echo "  Typical Linux setup:"
	@echo "    make install-tools"
	@echo "    make all"
	@echo "    make run"

install-tools:
	cargo install bpf-linker
	cargo install aya-tool

generate-vmlinux:
	cargo run --package xtask generate-vmlinux

build-ebpf:
	cargo run --package xtask build-ebpf --release

build:
	cargo build --release

all: generate-vmlinux build-ebpf build

run:
	sudo ./target/release/spica

clean:
	cargo clean

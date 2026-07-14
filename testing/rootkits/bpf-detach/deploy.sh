#!/bin/bash
# R4/R8: Tracepoint detach — remove SPiCa's sched_switch program.
#
# This simulates a rootkit detaching SPiCa's observation channel.
# Expected: [TAMPER] within ~2s (NMI heartbeat detects sched stopped)
#
# Uses bpftool to find and detach SPiCa's sched_switch tracepoint program.
# Requires bpftool and CAP_SYS_ADMIN.

set -euo pipefail

echo "[R4/R8]      Tracepoint detach attack"

if ! command -v bpftool >/dev/null 2>&1; then
    echo "[INSTALL]    Installing bpftool..."
    apt-get install -y bpftool 2>/dev/null || \
    dnf install -y bpftool 2>/dev/null || \
    pacman -S --noconfirm bpftool 2>/dev/null || {
        echo "[ERROR]      bpftool not available — cannot detach program"
        exit 1
    }
fi

# ── Find SPiCa's sched_switch tracepoint program ────────────────────────────
echo "[SCAN]       Looking for SPiCa's BPF programs..."

# List all loaded BPF programs
SPICA_PROG_ID=$(bpftool prog show 2>/dev/null | \
    grep -B1 "spica_sched" | \
    head -1 | \
    grep -o '[0-9]\+:' | \
    tr -d ':')

if [ -z "$SPICA_PROG_ID" ]; then
    echo "[ERROR]      spica_sched program not found in bpftool prog show"
    echo "[DEBUG]      Current BPF programs:"
    bpftool prog show 2>/dev/null | head -20
    exit 1
fi

echo "[FOUND]      spica_sched program ID: $SPICA_PROG_ID"

# ── Detach the program from the tracepoint ──────────────────────────────────
echo "[ATTACK]     Detaching spica_sched from sched_switch..."

# Try to detach via bpftool
bpftool prog detach "$SPICA_PROG_ID" tracepoint 2>&1 || {
    echo "[ATTACK]     Direct detach failed — trying link-based detach..."
    # Newer kernels use bpf_link. Try to find and detach the link.
    for link_id in $(bpftool link show 2>/dev/null | grep -o '[0-9]\+:' | tr -d ':'); do
        if bpftool link show id "$link_id" 2>/dev/null | grep -q "prog_id $SPICA_PROG_ID"; then
            echo "[ATTACK]     Found bpf_link $link_id — forcing detach..."
            bpftool link detach id "$link_id" 2>&1 || true
        fi
    done
}

# ── Verify detachment ────────────────────────────────────────────────────────
sleep 1
if bpftool prog show id "$SPICA_PROG_ID" 2>/dev/null | grep -q "sched_switch"; then
    echo "[VERIFY]     Program still attached to sched_switch"
    echo "[VERIFY]     Detach may have failed (CAP_SYS_ADMIN needed?)"
else
    echo "[VERIFY]     sched_switch detached successfully"
    echo "[VERIFY]     SPiCa should fire [TAMPER] within 2s (heartbeat frozen)"
fi

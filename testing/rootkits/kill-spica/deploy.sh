#!/bin/bash
# R6: Kill SPiCa userspace process.
#
# Simulates an attacker killing SPiCa to blind the detection system.
# Expected: SPiCa's watchdog (BPF tracepoint on sched_process_exit)
# sets the forensic kill flag in a pinned BPF map. On next startup,
# SPiCa detects the leftover pin and fires [WATCHDOG].

set -euo pipefail

echo "[R6]         Kill SPiCa userspace process"

# ── Find and kill SPiCa ─────────────────────────────────────────────────────
SPICA_PID=$(pgrep -x spica || true)

if [ -z "$SPICA_PID" ]; then
    echo "[ERROR]      SPiCa process not found"
    exit 1
fi

echo "[FOUND]      SPiCa PID: $SPICA_PID"

# Record the kill timestamp
echo "[ATTACK]     Sending SIGKILL to SPiCa (PID $SPICA_PID)..."
kill -9 "$SPICA_PID"

sleep 1

# Verify the process is dead
if pgrep -x spica >/dev/null 2>&1; then
    echo "[WARN]       SPiCa still running — SIGKILL may have failed"
else
    echo "[VERIFY]     SPiCa process terminated"
fi

# ── Check watchdog pin ──────────────────────────────────────────────────────
echo "[CHECK]      Checking watchdog pin at /sys/fs/bpf/spica_watchdog..."

if [ -f /sys/fs/bpf/spica_watchdog ]; then
    echo "[VERIFY]     Watchdog pin EXISTS — forensic evidence preserved"
    echo "[VERIFY]     The pin outlived SIGKILL (BPF-FS pins survive process death)"
    echo "[VERIFY]     On next SPiCa startup, [WATCHDOG] will fire"
else
    echo "[WARN]       Watchdog pin NOT found"
    echo "[WARN]       Either SPiCa wasn't killed cleanly, or the pin failed"
fi

# ── Check if sc_wd flag was set ─────────────────────────────────────────────
echo "[CHECK]      Reading watchdog flag value..."
# The flag is in the pinned map. We can read it with bpftool if available.
if command -v bpftool >/dev/null 2>&1; then
    WD_MAP_ID=$(bpftool map show 2>/dev/null | grep "spica_watchdog" | head -1 | grep -o '[0-9]\+:' | tr -d ':')
    if [ -n "$WD_MAP_ID" ]; then
        echo "[CHECK]      Watchdog map ID: $WD_MAP_ID"
        bpftool map lookup id "$WD_MAP_ID" key 0 0 0 0 2>/dev/null || true
    fi
fi

echo ""
echo "[RESULT]     SPiCa killed. Watchdog evidence at /sys/fs/bpf/spica_watchdog"
echo "[RESULT]     Restart SPiCa to verify [WATCHDOG] alert fires"

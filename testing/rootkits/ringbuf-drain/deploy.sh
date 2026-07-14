#!/bin/bash
# R7: Ring buffer drain — simulate event suppression at the data path.
#
# This test doesn't actually manipulate the ring buffer consumer pointer
# (that requires arbitrary kernel write, outside the eBPF threat model).
# Instead, it verifies that SPiCa detects the SYMPTOM: sched events
# stop arriving while /proc is still populated.
#
# We simulate this by detaching SPiCa's sched ring buffer (if possible)
# or by saturating the ring buffer to cause drops.
#
# Expected: [SILENT] within 5s if events stop flowing

set -euo pipefail

echo "[R7]         Ring buffer / event suppression test"

# ── Method 1: Detach the perf event to stop NMI heartbeats ──────────────────
# This simulates the perf_event struct DKOM attack (zeroing the state field).
echo "[ATTACK]     Attempting to detach NMI perf event..."

if ! command -v bpftool >/dev/null 2>&1; then
    apt-get install -y bpftool 2>/dev/null || dnf install -y bpftool 2>/dev/null || true
fi

# Find SPiCa's NMI perf event program
NMI_PROG_ID=$(bpftool prog show 2>/dev/null | grep -B1 "spica_nmi" | head -1 | grep -o '[0-9]\+:' | tr -d ':' || true)

if [ -n "$NMI_PROG_ID" ]; then
    echo "[FOUND]      spica_nmi program ID: $NMI_PROG_ID"

    # Try to detach perf event programs (they use perf_event links)
    for link_id in $(bpftool link show 2>/dev/null | grep -o '[0-9]\+:' | tr -d ':' || true); do
        if bpftool link show id "$link_id" 2>/dev/null | grep -q "prog_id $NMI_PROG_ID"; then
            echo "[ATTACK]     Detaching NMI perf link $link_id..."
            bpftool link detach id "$link_id" 2>&1 || true
        fi
    done
else
    echo "[SKIP]       spica_nmi program not found via bpftool"
fi

# ── Method 2: Flood the sched ring buffer to cause overflow ─────────────────
echo ""
echo "[ATTACK]     Flooding scheduler with short-lived processes..."
echo "             (testing ring buffer overflow handling)"

# Create many short-lived processes to generate massive sched events
for i in $(seq 1 10000); do
    true &
done
wait

echo "[VERIFY]     Flood complete"
echo "[RESULT]     Check SPiCa output for any [SILENT] or missed detections"
echo "[RESULT]     If ring buffer overflowed, some events were dropped but"
echo "             channel-level SILENT should NOT fire (sched_last still fresh)"

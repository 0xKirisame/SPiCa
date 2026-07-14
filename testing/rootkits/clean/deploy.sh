#!/bin/bash
# N1/N2/N3: Negative test — clean system, no rootkit.
#
# Verifies zero false positives over the test duration.
# Expected: 0 alerts of any kind.
#
# Usage: deploy.sh [duration_minutes]
# Default: 10 minutes

set -euo pipefail

DURATION_MIN="${1:-10}"
DURATION_SEC=$((DURATION_MIN * 60))

echo "[N1/N2/N3]   Negative test — clean system"
echo "             Duration: ${DURATION_MIN} minutes ($DURATION_SEC seconds)"
echo "             Expected: ZERO alerts"

# Record start alert count
ALERTS_BEFORE=$(grep -c '\[DKOM\]\|\[GHOST\]\|\[TAMPER\]\|\[SILENT\]\|\[DUPE\]\|\[WATCHDOG\]' /tmp/spica.log 2>/dev/null || echo "0")
echo "             Alerts before: $ALERTS_BEFORE"

# ── Workload simulation ─────────────────────────────────────────────────────
echo ""
echo "[WORKLOAD]   Running mixed workload..."

# Simulate realistic activity
END_TIME=$((SECONDS + DURATION_SEC))
WORKLOAD_PID=""

while [ "$SECONDS" -lt "$END_TIME" ]; do
    # Compile something (CPU + I/O)
    if command -v gcc >/dev/null 2>&1; then
        echo 'int main(){return 0;}' > /tmp/null_test.c
        gcc -O2 /tmp/null_test.c -o /tmp/null_test 2>/dev/null || true
    fi

    # Fork some short-lived processes
    for i in $(seq 1 50); do
        true &
    done

    # Disk I/O
    dd if=/dev/zero of=/tmp/null_write bs=1M count=10 2>/dev/null || true
    rm -f /tmp/null_write

    # Network activity (if available)
    if command -v curl >/dev/null 2>&1; then
        curl -s --max-time 2 http://localhost >/dev/null 2>&1 || true
    fi

    sleep 5
done

# ── Record results ──────────────────────────────────────────────────────────
ALERTS_AFTER=$(grep -c '\[DKOM\]\|\[GHOST\]\|\[TAMPER\]\|\[SILENT\]\|\[DUPE\]\|\[WATCHDOG\]' /tmp/spica.log 2>/dev/null || echo "0")
NEW_ALERTS=$((ALERTS_AFTER - ALERTS_BEFORE))

echo ""
echo "[RESULT]     Alerts before: $ALERTS_BEFORE"
echo "[RESULT]     Alerts after:  $ALERTS_AFTER"
echo "[RESULT]     New alerts:    $NEW_ALERTS"

if [ "$NEW_ALERTS" -eq 0 ]; then
    echo "[PASS]       Zero false positives over ${DURATION_MIN} minutes"
else
    echo "[FAIL]       $NEW_ALERTS false positive(s) detected!"
    echo "[DEBUG]      Alert lines:"
    grep '\[DKOM\]\|\[GHOST\]\|\[TAMPER\]\|\[SILENT\]\|\[DUPE\]\|\[WATCHDOG\]' /tmp/spica.log 2>/dev/null | tail -10
fi

#!/bin/bash
# Generic test runner for a single rootkit/attack test case.
#
# Boots a fresh overlay VM, installs SPiCa, deploys the attack, waits
# for detection, and records the result as JSON.
#
# Usage: test-runner.sh <base-image> <test-id> <distro> <deploy-script> [ssh_port]
# Example: test-runner.sh ~/vm/ubuntu-base.qcow2 R2-diamorphine ubuntu rootkits/diamorphine/deploy.sh

set -euo pipefail

BASE_IMAGE="${1:?Usage: $0 <base-image> <test-id> <distro> <deploy-script> [ssh_port]}"
TEST_ID="${2:?Missing test-id}"
DISTRO="${3:?Missing distro}"
DEPLOY_SCRIPT="${4:?Missing deploy-script}"
SSH_PORT="${5:-2222}"

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OVERLAY_NAME="${TEST_ID}-${DISTRO}"
RESULT_FILE="$RESULTS_DIR/${OVERLAY_NAME}.json"
SPICA_LOG="$RESULTS_DIR/${OVERLAY_NAME}-spica.log"
SSH="ssh -p $SSH_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@localhost"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Test: $TEST_ID"
echo "║  Distro: $DISTRO"
echo "║  Timestamp: $TIMESTAMP"
echo "╚══════════════════════════════════════════════════════════╝"

# ── Create overlay ──────────────────────────────────────────────────────────
echo "[1/8] Creating overlay..."
OVERLAY=$($SCRIPT_DIR/vm/create-overlay.sh "$BASE_IMAGE" "$OVERLAY_NAME")
echo "      $OVERLAY"

# ── Boot VM ─────────────────────────────────────────────────────────────────
echo "[2/8] Booting hardened VM..."
$SCRIPT_DIR/vm/boot-hardened.sh "$OVERLAY" "$SSH_PORT"

# ── Wait for SSH ────────────────────────────────────────────────────────────
echo "[3/8] Waiting for SSH..."
for i in $(seq 1 60); do
    if $SSH 'echo ok' >/dev/null 2>&1; then
        echo "      SSH connected after ${i}s"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "[FAIL]      SSH not reachable after 60s"
        cat "$RESULTS_DIR/vm-logs/${OVERLAY_NAME}-serial.log" 2>/dev/null | tail -30
        RESULT='{"test_id":"'$TEST_ID'","distro":"'$DISTRO'","detected":false,"error":"ssh_timeout"}'
        echo "$RESULT" > "$RESULT_FILE"
        exit 1
    fi
    sleep 1
done

# ── Get kernel version ─────────────────────────────────────────────────────
KERNEL=$($SSH 'uname -r' 2>/dev/null || echo "unknown")
echo "      Kernel: $KERNEL"

# ── Copy and start SPiCa ───────────────────────────────────────────────────
echo "[4/8] Installing SPiCa..."
SPICA_BIN="$SCRIPT_DIR/../target/release/spica"
if [ ! -f "$SPICA_BIN" ]; then
    echo "[FAIL]      SPiCa binary not found at $SPICA_BIN"
    echo "            Run: cargo build --release"
    exit 1
fi
scp -P "$SSH_PORT" -o StrictHostKeyChecking=no "$SPICA_BIN" root@localhost:/usr/local/bin/spica 2>/dev/null
$SSH 'chmod +x /usr/local/bin/spica'

echo "[5/8] Starting SPiCa..."
# Start SPiCa in background, capture output to log file
$SSH "nohup /usr/local/bin/spica > /tmp/spica.log 2>&1 & echo \$!" 2>/dev/null
sleep 5

# Check SPiCa is running
if ! $SSH 'pgrep -x spica >/dev/null' 2>/dev/null; then
    echo "[FAIL]      SPiCa failed to start"
    $SSH 'cat /tmp/spica.log' 2>/dev/null
    RESULT='{"test_id":"'$TEST_ID'","distro":"'$DISTRO'","detected":false,"error":"spica_start_failed"}'
    echo "$RESULT" > "$RESULT_FILE"
    exit 1
fi

# Capture initial output (security stack status)
$SSH 'cat /tmp/spica.log' > "$SPICA_LOG" 2>/dev/null
echo "      SPiCa running. Startup output:"
head -20 "$SPICA_LOG" | sed 's/^/      /'

# ── Deploy attack ───────────────────────────────────────────────────────────
ATTACK_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[6/8] Deploying attack: $DEPLOY_SCRIPT"

if [ -f "$SCRIPT_DIR/$DEPLOY_SCRIPT" ]; then
    # Copy deploy script to VM and execute
    scp -P "$SSH_PORT" -o StrictHostKeyChecking=no \
        "$SCRIPT_DIR/$DEPLOY_SCRIPT" root@localhost:/tmp/deploy.sh 2>/dev/null
    $SSH 'bash /tmp/deploy.sh' 2>&1 | sed 's/^/      /'
elif [ -f "$DEPLOY_SCRIPT" ]; then
    scp -P "$SSH_PORT" -o StrictHostKeyChecking=no \
        "$DEPLOY_SCRIPT" root@localhost:/tmp/deploy.sh 2>/dev/null
    $SSH 'bash /tmp/deploy.sh' 2>&1 | sed 's/^/      /'
else
    echo "      Deploy script not found: $DEPLOY_SCRIPT"
    echo "      Running as SSH command directly..."
    $SSH "$DEPLOY_SCRIPT" 2>&1 | sed 's/^/      /'
fi

# ── Wait for detection ─────────────────────────────────────────────────────
echo "[7/8] Waiting for detection (up to 30s)..."
DETECTED="false"
ALERT_CLASS=""
DETECT_TIME=""

for i in $(seq 1 30); do
    sleep 1
    # Pull latest SPiCa output
    $SSH 'cat /tmp/spica.log' >> "$SPICA_LOG" 2>/dev/null

    # Check for alert lines (look for [DKOM], [TAMPER], [SILENT], [LKM-DENY], [WATCHDOG])
    ALERT=$($SSH 'grep -o "\[DKOM\]\|\[GHOST\]\|\[TAMPER\]\|\[SILENT\]\|\[LKM-DENY\]\|\[LKM-ALLOW\]\|\[WATCHDOG\]\|\[DUPE\]" /tmp/spica.log | tail -1' 2>/dev/null || echo "")

    if [ -n "$ALERT" ]; then
        DETECTED="true"
        ALERT_CLASS=$(echo "$ALERT" | tr -d '[]')
        DETECT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        echo "      DETECTED: $ALERT after ${i}s"
        break
    fi
done

if [ "$DETECTED" = "false" ]; then
    echo "      No detection within 30s"
fi

# ── Collect final output ───────────────────────────────────────────────────
echo "[8/8] Collecting results..."
$SSH 'cat /tmp/spica.log' >> "$SPICA_LOG" 2>/dev/null

# Check system stability
STABLE="true"
if ! $SSH 'uname -r' >/dev/null 2>&1; then
    STABLE="false"
    echo "      [WARN] VM unresponsive — possible crash"
fi

# Shutdown VM
$SSH 'poweroff' 2>/dev/null || kill $(cat "$RESULTS_DIR/vm-logs/${OVERLAY_NAME}.pid" 2>/dev/null) 2>/dev/null || true
sleep 3

# ── Write result JSON ───────────────────────────────────────────────────────
LATENCY="null"
if [ "$DETECTED" = "true" ]; then
    LATENCY=$i
fi

cat > "$RESULT_FILE" << EOF
{
  "test_id": "$TEST_ID",
  "distro": "$DISTRO",
  "kernel": "$KERNEL",
  "timestamp": "$TIMESTAMP",
  "attack_time": "$ATTACK_TIME",
  "detected": $DETECTED,
  "alert_class": "${ALERT_CLASS:-none}",
  "latency_sec": $LATENCY,
  "system_stable": $STABLE,
  "spica_log": "${SPICA_LOG#$SCRIPT_DIR/}"
}
EOF

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Result: $(if [ "$DETECTED" = "true" ]; then echo "✓ DETECTED ($ALERT_CLASS, ${i}s)"; else echo "✗ NOT DETECTED"; fi)"
echo "  Stable: $STABLE"
echo "  Result: $RESULT_FILE"
echo "════════════════════════════════════════════════════════════"

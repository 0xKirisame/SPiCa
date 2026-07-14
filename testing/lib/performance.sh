#!/bin/bash
# Performance benchmarking — measures SPiCa's overhead.
# Run with SPiCa active, then compare against a baseline (SPiCa stopped).
#
# Usage: performance.sh <ssh_port>
# Outputs a JSON result file with all metrics.

set -euo pipefail

SSH_PORT="${1:-2222}"
SSH="ssh -p $SSH_PORT -o StrictHostKeyChecking=no root@localhost"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RESULT_FILE="$SCRIPT_DIR/results/performance.json"

echo "[PERF]       Performance benchmarking"
echo "             SSH: localhost:$SSH_PORT"

# ── Install benchmarking tools ──────────────────────────────────────────────
echo "[SETUP]      Installing benchmarking tools..."
$SSH 'apt-get install -y perf-tools-unstable stress-ng iperf3 2>/dev/null || dnf install -y stress-ng iperf3 2>/dev/null || pacman -S --noconfirm stress-ng iperf3 2>/dev/null || true' 2>/dev/null

run_bench() {
    local NAME="$1"
    local CMD="$2"
    local DURATION="${3:-10}"

    echo ""
    echo "[BENCH]      $NAME"

    # Run with SPiCa
    local WITH_SPICA
    WITH_SPICA=$($SSH "timeout $DURATION $CMD" 2>&1 || echo "FAILED")
    echo "             With SPiCa:    $WITH_SPICA"

    # Stop SPiCa
    $SSH 'pkill -x spica 2>/dev/null || true'
    sleep 2

    # Run without SPiCa
    local WITHOUT_SPICA
    WITHOUT_SPICA=$($SSH "timeout $DURATION $CMD" 2>&1 || echo "FAILED")
    echo "             Without SPiCa: $WITHOUT_SPICA"

    # Restart SPiCa
    $SSH 'nohup /usr/local/bin/spica > /tmp/spica.log 2>&1 &'
    sleep 3

    echo "$WITH_SPICA|$WITHOUT_SPICA"
}

# ── CPU idle ────────────────────────────────────────────────────────────────
echo ""
echo "═══ CPU Utilization ═══"
IDLE_WITH=$($SSH 'top -bn1 | grep "Cpu(s)" | awk "{print \$2}"' 2>/dev/null || echo "?")
echo "             Idle CPU usage (with SPiCa): $IDLE_WITH%"

# ── Context switch latency ──────────────────────────────────────────────────
echo ""
echo "═══ Context Switch Latency ═══"
echo "[BENCH]      perf sched messaging (with SPiCa)..."
SCHED_WITH=$($SSH 'perf bench sched messaging -l 10000 2>&1 | grep "Total time" || echo "N/A"' 2>/dev/null || echo "perf not available")
echo "             $SCHED_WITH"

$SSH 'pkill -x spica 2>/dev/null || true'; sleep 2
echo "[BENCH]      perf sched messaging (without SPiCa)..."
SCHED_WITHOUT=$($SSH 'perf bench sched messaging -l 10000 2>&1 | grep "Total time" || echo "N/A"' 2>/dev/null || echo "perf not available")
echo "             $SCHED_WITHOUT"

$SSH 'nohup /usr/local/bin/spica > /tmp/spica.log 2>&1 &'; sleep 3

# ── Memory ──────────────────────────────────────────────────────────────────
echo ""
echo "═══ Memory Overhead ═══"
RSS=$($SSH 'ps -o rss= -p $(pgrep -x spica) 2>/dev/null | awk "{print \$1}"' 2>/dev/null || echo "0")
RSS_KB=${RSS:-0}
RSS_MB=$(echo "scale=1; $RSS_KB / 1024" | bc 2>/dev/null || echo "?")
echo "             SPiCa RSS: ${RSS_MB}MB"

# BPF maps memory
BPF_MEM=$($SSH 'bpftool map show 2>/dev/null | grep -o "bytes [0-9]*" | awk "{sum+=\$2} END {print sum/1024}"' 2>/dev/null || echo "0")
echo "             BPF maps total: ${BPF_MEM}KB"

# ── Stress test ─────────────────────────────────────────────────────────────
echo ""
echo "═══ Stress-ng (60s) ═══"
echo "[BENCH]      stress-ng --cpu 4 --timeout 60 (with SPiCa)..."
STRESS_WITH=$($SSH 'stress-ng --cpu 4 --timeout 60 --metrics-brief 2>&1 | tail -1' 2>/dev/null || echo "stress-ng not available")
echo "             $STRESS_WITH"

# ── Write results ───────────────────────────────────────────────────────────
echo ""
echo "[RESULT]     Writing $RESULT_FILE"

cat > "$RESULT_FILE" << EOF
{
  "benchmark_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel": "$($SSH 'uname -r' 2>/dev/null)",
  "metrics": {
    "idle_cpu_pct_with_spica": "$IDLE_WITH",
    "sched_messaging_with_spica": "$(echo "$SCHED_WITH" | tr -d '"')",
    "sched_messaging_without_spica": "$(echo "$SCHED_WITHOUT" | tr -d '"')",
    "spica_rss_mb": "$RSS_MB",
    "bpf_maps_kb": "$BPF_MEM",
    "stress_ng_60s": "$(echo "$STRESS_WITH" | tr -d '"')"
  }
}
EOF

echo "[DONE]       Benchmark complete: $RESULT_FILE"

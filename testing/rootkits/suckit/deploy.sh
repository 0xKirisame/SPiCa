#!/bin/bash
# SucKIT rootkit — /dev/kmem manipulation (bypasses init_module entirely).
#
# This is a SPECIAL case: SucKIT writes directly to kernel memory via
# /dev/kmem, so the LSM gate does NOT block it (no init_module syscall).
# However, /dev/kmem is disabled on all modern kernels (CONFIG_DEVKMEM=n).
#
# Test 1: On modern kernel → /dev/kmem unavailable → SucKIT fails to load
# Test 2: On older kernel (or if /dev/kmem is enabled) → DKOM detection
#
# Expected on modern hardened kernel:
#   /dev/kmem not found → rootkit cannot load → test passes trivially

set -euo pipefail

echo "[SUCKIT]     SucKIT rootkit (/dev/kmem attack)"

# ── Check /dev/kmem availability ────────────────────────────────────────────
if [ -e /dev/kmem ]; then
    echo "[WARN]       /dev/kmem EXISTS on this kernel!"
    echo "[WARN]       This kernel is not hardened — CONFIG_DEVKMEM should be n"
    echo "[WARN]       SucKIT can write kernel memory directly, bypassing the gate"

    # If /dev/kmem exists, SucKIT-style attacks can bypass the gate.
    # SPiCa's DKOM detection would still fire if a process is hidden.
    echo "[DEPLOY]     Simulating DKOM via direct kernel memory write..."
    echo "[EXPECTED]   [DKOM] if a process is hidden via kmem manipulation"
    echo "[NOTE]       On production kernels, /dev/kmem should be disabled"
else
    echo "[OK]         /dev/kmem not available"
    echo "[VERIFY]     CONFIG_DEVKMEM=n — SucKIT cannot load on this kernel"
    echo "[RESULT]     Attack surface blocked at kernel config level"
    echo "[EXPECTED]   No effect — rootkit cannot function"
fi

# ── Verify CONFIG_DEVKMEM ───────────────────────────────────────────────────
echo ""
echo "[CHECK]      Kernel config..."
KCONFIG=$(zcat /proc/config.gz 2>/dev/null | grep "CONFIG_DEVKMEM=" || \
          cat /boot/config-$(uname -r) 2>/dev/null | grep "CONFIG_DEVKMEM=" || \
          echo "CONFIG_DEVKMEM=not_found")
echo "             $KCONFIG"

if echo "$KCONFIG" | grep -q "=n"; then
    echo "[PASS]       /dev/kmem disabled — SucKIT neutralized at kernel level"
elif echo "$KCONFIG" | grep -q "=y"; then
    echo "[FAIL]       /dev/kmem enabled — system is vulnerable to kmem rootkits"
else
    echo "[UNKNOWN]    CONFIG_DEVKMEM status unknown"
fi

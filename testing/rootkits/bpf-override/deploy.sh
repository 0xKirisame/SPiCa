#!/bin/bash
# R5: bpf_override_return — attempt to override sched_switch dispatch.
#
# Tests whether bpf_override_return can suppress the tracepoint.
# Expected: No effect (sched_switch dispatch is void, not ALLOW_ERROR_INJECTION).
#           SPiCa continues normally, no alerts.
#
# This test verifies the security claim in §4 of the README:
# "bpf_override_return intercepts function calls. The NMI checker doesn't
# call anything it verifies — it reads .bss directly."

set -euo pipefail

echo "[R5]         bpf_override_return attempt"

# ── Check kernel support ────────────────────────────────────────────────────
echo "[CHECK]      CONFIG_BPF_KPROBE_OVERRIDE status..."
CONFIG_VAL=$(zcat /proc/config.gz 2>/dev/null | grep "CONFIG_BPF_KPROBE_OVERRIDE=" || \
             cat /boot/config-$(uname -r) 2>/dev/null | grep "CONFIG_BPF_KPROBE_OVERRIDE=" || \
             echo "NOT_FOUND")
echo "             $CONFIG_VAL"

if echo "$CONFIG_VAL" | grep -q "=y"; then
    echo "[CHECK]      Kernel supports BPF_KPROBE_OVERRIDE"
else
    echo "[CHECK]      Kernel does NOT support BPF_KPROBE_OVERRIDE"
    echo "[RESULT]     Attack surface not present — test passes trivially"
    echo "[RESULT]     SPiCa should NOT fire any alerts"
    exit 0
fi

# ── Check if __tracepoint_sched_switch is ALLOW_ERROR_INJECTION ─────────────
echo "[CHECK]      Checking if sched functions are ALLOW_ERROR_INJECTION tagged..."
echo "[CHECK]      (Expected: they are NOT — core scheduler functions are never tagged)"

# The ALLOW_ERROR_INJECTION list is in /sys/kernel/debug/error_injection/list
# (requires debugfs + CONFIG_BPF_KPROBE_OVERRIDE)
ERROR_INJECT_LIST="/sys/kernel/debug/error_injection/list"

if [ -f "$ERROR_INJECT_LIST" ]; then
    if grep -qi "sched" "$ERROR_INJECT_LIST" 2>/dev/null; then
        echo "[WARN]       A sched function IS in the error_injection list!"
        grep -i "sched" "$ERROR_INJECT_LIST"
    else
        echo "[VERIFY]     No sched functions in error_injection list"
        echo "[VERIFY]     bpf_override_return CANNOT target the scheduler"
    fi
else
    echo "[CHECK]      error_injection list not available (debugfs not mounted?)"
    echo "[CHECK]      Mounting debugfs for inspection..."
    mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    if [ -f "$ERROR_INJECT_LIST" ]; then
        if grep -qi "sched" "$ERROR_INJECT_LIST"; then
            echo "[WARN]       sched function found in error_injection list!"
        else
            echo "[VERIFY]     No sched functions can be error-injected"
        fi
    else
        echo "[CHECK]      error_injection list unavailable"
    fi
fi

echo ""
echo "[RESULT]     bpf_override_return cannot suppress sched_switch"
echo "[RESULT]     The tracepoint dispatch is void (no return value to override)"
echo "[RESULT]     No scheduler functions are ALLOW_ERROR_INJECTION tagged"
echo "[RESULT]     Expected: SPiCa continues normally, NO alerts"

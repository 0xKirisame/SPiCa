// SPDX-License-Identifier: GPL-2.0
// Minimal .bss-global program exercising the freeze semantics that SPiCa's
// ledger depends on. No vmlinux.h — nothing is read from ctx (mirrors
// SPiCa's non-BTF discipline).
//
// State is a SINGLE struct global so the .bss byte layout is deterministic
// (C struct field order) regardless of how the linker orders top-level
// symbols — v1 of this harness got byte-swapped fields that way.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct state {
    long base_key;    // "secret" written by the loader pre-freeze
    long heartbeat;   // spoof target (pre-freeze) / prog-written
    long seq;         // incremented on every fork
};

struct state g_state = {};   // zero-initialized → .bss

SEC("tracepoint/sched/sched_process_fork")
int tp_fork(void *ctx)
{
    g_state.seq++;
    g_state.heartbeat = bpf_ktime_get_ns();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

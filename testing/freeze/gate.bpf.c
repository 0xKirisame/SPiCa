// SPDX-License-Identifier: GPL-2.0
// Two lsm/bpf programs for the deny-wins test (see gate_harness.c).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

int exempt_pid;   // .bss, set by the loader pre-attach

SEC("lsm/bpf")
int BPF_PROG(deny_gate, int cmd)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    if (cmd == BPF_MAP_GET_FD_BY_ID && tgid != (__u32)exempt_pid)
        return -EPERM;
    return 0;
}

SEC("lsm/bpf")
int BPF_PROG(allow_all, int cmd)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

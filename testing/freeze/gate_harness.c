// SPDX-License-Identifier: GPL-2.0
// Deny-by-default bpf() LSM gate test — the SPiCa stage-1 mechanism.
//
// Loads TWO lsm/bpf programs:
//   deny_gate  — returns -EPERM for BPF_MAP_GET_FD_BY_ID when the caller's
//                TGID != exempt_pid (set to the harness pid pre-attach)
//   allow_all  — returns 0 for everything
//
// T8 assertions:
//   a) the exempt process can still GET_FD_BY_ID (self-exemption works)
//   b) another process (bpftool) is denied EPERM even though a second,
//      later-attached LSM program returned 0 — deny-wins stacking
//
// The deny is deliberately scoped to BPF_MAP_GET_FD_BY_ID only, so even a
// bug in this test cannot wedge the VM's userspace (reboot also clears it:
// nothing persists).
//
// Build:  gcc gate_harness.c -o gate_harness -lbpf -lelf -lz

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *pdeny, *pallow;
    struct bpf_link *ldeny = NULL, *lallow = NULL;
    struct bpf_map *bss = NULL;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open_file("gate.bpf.o", NULL);
    if (!obj) { printf("[FAIL] open: %s\n", strerror(errno)); return 1; }
    if (bpf_object__load(obj)) { printf("[FAIL] load: %s\n", strerror(errno)); return 1; }

    // Find the .bss map and write exempt_pid pre-attach.
    bss = bpf_object__find_map_by_name(obj, "gate.bss");
    if (!bss) {
        // name may vary; fall back to any *.bss
        struct bpf_map *m;
        bpf_object__for_each_map(m, obj)
            if (strstr(bpf_map__name(m), ".bss")) { bss = m; break; }
    }
    if (!bss) { printf("[FAIL] no .bss map\n"); return 1; }
    int key = 0;
    struct { int exempt_pid; } v = { .exempt_pid = getpid() };
    if (bpf_map_update_elem(bpf_map__fd(bss), &key, &v, 0)) {
        printf("[FAIL] set exempt_pid: %s\n", strerror(errno));
        return 1;
    }

    pdeny = bpf_object__find_program_by_name(obj, "deny_gate");
    pallow = bpf_object__find_program_by_name(obj, "allow_all");
    ldeny = bpf_program__attach(pdeny);
    lallow = bpf_program__attach(pallow);
    if (!ldeny || !lallow) { printf("[FAIL] attach: %s\n", strerror(errno)); return 1; }
    printf("[INFO] gate armed: exempt_pid=%d, deny=BPF_MAP_GET_FD_BY_ID, allow_all attached\n", getpid());

    // (a) self-exemption: we can still enumerate
    __u32 id = 0, next = 0;
    int ok = 0;
    while (bpf_map_get_next_id(id, &next) == 0) {
        int fd = bpf_map_get_fd_by_id(next);   // must be allowed for us
        if (fd >= 0) { close(fd); ok++; }
        id = next;
    }
    if (ok > 0)
        printf("[PASS] T-8a exempt process can GET_FD_BY_ID (%d maps)\n", ok);
    else
        printf("[FAIL] T-8a exempt process was denied too\n");

    // (b) deny-wins: another process (bpftool) must be denied. We find a map
    // id first (we're exempt), then ask bpftool — a different process — to
    // open it by id. bpftool needs GET_FD_BY_ID for `dump id N`.
    __u32 probe_id = id;   // last enumerated id
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "bpftool map dump id %u >/tmp/gate_out 2>&1", probe_id);
    int rc = system(cmd);
    FILE *f = fopen("/tmp/gate_out", "r");
    char out[256] = {0};
    if (f) { size_t n = fread(out, 1, sizeof(out) - 1, f); (void)n; fclose(f); }
    if (rc != 0 && strstr(out, "Operation not permitted"))
        printf("[PASS] T-8b other process denied (deny-wins over allow_all): %s",
               out[0] ? out : "EPERM\n");
    else
        printf("[FAIL] T-8b bpftool not denied (rc=%d, out=%s)\n", rc, out);

    bpf_link__destroy(ldeny);
    bpf_link__destroy(lallow);
    bpf_object__close(obj);
    printf("[INFO] gate detached\n");
    return 0;
}

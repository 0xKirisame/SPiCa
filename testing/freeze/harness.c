// SPDX-License-Identifier: GPL-2.0
// Freeze semantics harness — raw libbpf object API, NO skeleton.
//
// A skeleton holds a writable mmap of .bss, and map_freeze() returns EBUSY
// while any writable mapping is outstanding (writecnt) — empirically
// confirmed by v2 of this harness. SPiCa's aya loader does NOT mmap globals
// (initial values go through the update syscall), so this harness mirrors
// the aya pattern: open/load/attach, raw-syscall updates, freeze, verify.
//
//   T1  id-enumerated read of the .bss map leaks base_key (separate process)
//   T2  pre-freeze BPF_MAP_UPDATE_ELEM rewrites .bss state (the old hole)
//   T3  bpf_map_freeze() → syscall update returns EPERM
//   T4  program writes to the frozen map keep working
//   T5  fdinfo reports frozen:1
//   T6  second freeze fails (EPERM on v6.8; EBUSY acceptable elsewhere)
//   T7  a different privileged process can freeze a map it does not own
//
// Build:  clang -target bpf -O2 -g -c test.bpf.c -o test.bpf.o
//         gcc harness.c -o harness -lbpf -lelf -lz

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PASS(name) printf("[PASS] T-%s\n", name)
#define FAIL(name, why) printf("[FAIL] T-%s: %s\n", name, (why))

/* mirrors struct state in test.bpf.c */
struct state {
    long base_key;
    long heartbeat;
    long seq;
};

static int bss_fd(struct bpf_object *obj)
{
    struct bpf_map *m;
    bpf_object__for_each_map(m, obj) {
        const char *n = bpf_map__name(m);
        if (n && strstr(n, ".bss"))
            return bpf_map__fd(m);
    }
    return -1;
}

int main(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct bpf_object *obj = bpf_object__open_file("test.bpf.o", NULL);
    if (!obj) { FAIL("load", "open"); return 1; }
    if (bpf_object__load(obj)) { FAIL("load", strerror(errno)); return 1; }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tp_fork");
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) { FAIL("load", "attach"); return 1; }

    int fd = bss_fd(obj);
    if (fd < 0) { FAIL("load", "no test_bpf.bss"); return 1; }
    int key = 0;
    __u32 bss_id = 0;
    {
        struct bpf_map_info info = {};
        __u32 ilen = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &ilen) == 0) bss_id = info.id;
    }
    printf("[INFO] .bss map: test_bpf.bss id=%u\n", bss_id);

    // Loader writes the "secret" pre-freeze (SPiCa: override_global →
    // initial-value update syscall — exactly this).
    struct state v = { .base_key = 0xCAF000D0BEEF1234L };
    if (bpf_map_update_elem(fd, &key, &v, 0)) { FAIL("init", strerror(errno)); return 1; }

    // ── T2: pre-freeze spoof (the hole the old design was blind to) ────────
    {
        struct state cur = {0};
        if (bpf_map_lookup_elem(fd, &key, &cur) == 0 && cur.base_key == v.base_key) {
            cur.heartbeat = 0xDEAD1L;   // forged "fresh" heartbeat
            if (bpf_map_update_elem(fd, &key, &cur, 0) == 0) {
                struct state chk = {0};
                bpf_map_lookup_elem(fd, &key, &chk);
                if (chk.heartbeat == 0xDEAD1L)
                    PASS("2 pre-freeze UPDATE_ELEM spoofs .bss state (old hole confirmed)");
                else FAIL("2", "readback mismatch");
            } else FAIL("2", strerror(errno));
        } else FAIL("2", "initial write not observable");
    }

    // ── T3: freeze → syscall update must die ───────────────────────────────
    {
        int err = bpf_map_freeze(fd);
        if (err != 0) {
            printf("[FAIL] T-3 freeze: %s (EBUSY here means a writable mmap is still held)\n",
                   strerror(errno));
            return 1;
        }
        struct state cur = {0};
        bpf_map_lookup_elem(fd, &key, &cur);
        cur.heartbeat = 0xDEAD2L;
        err = bpf_map_update_elem(fd, &key, &cur, 0);
        if (err == -1 && errno == EPERM)
            PASS("3 frozen map rejects UPDATE_ELEM with EPERM");
        else
            FAIL("3", err ? strerror(errno) : "update unexpectedly SUCCEEDED");
    }

    // ── T4: program writes on the frozen map keep working ──────────────────
    {
        struct state before = {0}, after = {0};
        bpf_map_lookup_elem(fd, &key, &before);
        for (int i = 0; i < 50; i++)
            if (system("/bin/true") != 0) { /* fork happened regardless */ }
        bpf_map_lookup_elem(fd, &key, &after);
        if (after.seq > before.seq && after.heartbeat > before.heartbeat
            && after.heartbeat != 0xDEAD1L)
            PASS("4 program writes to frozen map work (seq + heartbeat advanced)");
        else
            FAIL("4", "prog writes did not advance state");
    }

    // ── T5: fdinfo shows frozen:1 ──────────────────────────────────────────
    {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
        FILE *f = fopen(path, "r");
        char line[256];
        int frozen = -1;
        if (f) {
            while (fgets(line, sizeof(line), f))
                if (sscanf(line, "frozen:\t%d", &frozen) == 1) break;
            fclose(f);
        }
        if (frozen == 1) PASS("5 fdinfo reports frozen:1");
        else FAIL("5", frozen == 0 ? "frozen:0" : "no frozen field");
    }

    // ── T6: second freeze must fail (EPERM on v6.8, EBUSY acceptable) ─────
    {
        int err = bpf_map_freeze(fd);
        if (err == -1 && (errno == EPERM || errno == EBUSY))
            printf("[PASS] T-6 second freeze rejected with %s (sealed signal)\n",
                   errno == EPERM ? "EPERM" : "EBUSY");
        else
            FAIL("6", err ? strerror(errno) : "second freeze unexpectedly SUCCEEDED");
    }

    // ── T7: cross-process freeze — no owner authentication ─────────────────
    {
        int m2 = bpf_map_create(BPF_MAP_TYPE_ARRAY, "t7_victim", sizeof(int),
                                sizeof(long), 1, NULL);
        if (m2 < 0) { FAIL("7", "map_create failed"); return 1; }
        __u32 m2_id = 0;
        struct bpf_map_info info = {};
        __u32 ilen = sizeof(info);
        bpf_obj_get_info_by_fd(m2, &info, &ilen);
        m2_id = info.id;
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "bpftool map freeze id %u 2>&1", m2_id);
        FILE *p = popen(cmd, "r");
        char out[256] = {0};
        size_t n = fread(out, 1, sizeof(out) - 1, p); (void)n;
        int rc = pclose(p);
        long val = 42;
        int k2 = 0;
        int upd = bpf_map_update_elem(m2, &k2, &val, 0);
        if (rc == 0 && upd == -1 && errno == EPERM)
            PASS("7 other process froze our map; our update now EPERMs (no owner auth)");
        else
            FAIL("7", rc ? out : "bpftool freeze ok but update still allowed?");
    }

    // ── T1: id-enumerated read from a separate process (the blunder) ───────
    {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "bpftool map dump id %u", bss_id);
        printf("[INFO] T-1: %s\n", cmd);
        fflush(stdout);
        int rc = system(cmd);
        printf("[INFO] (expect base_key 0xcaf000d0beef1234 above; rc=%d)\n", rc);
    }

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}

// SPDX-License-Identifier: GPL-2.0
// Load ONLY spica_lsm_bpfgate from the SPiCa eBPF object, with full libbpf
// verbose output, to expose the kernel's real rejection reason.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static int verbose(enum libbpf_print_level level, const char *fmt, va_list ap) {
    return vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv) {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(verbose);
    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) { fprintf(stderr, "open failed\n"); return 1; }
    struct bpf_program *p, *keep = NULL;
    bpf_object__for_each_program(p, obj) {
        int load = !strcmp(bpf_program__name(p), "spica_lsm_bpfgate");
        bpf_program__set_autoload(p, load);
        if (load) keep = p;
    }
    if (!keep) { fprintf(stderr, "prog not found\n"); return 1; }
    fprintf(stderr, "loading only: %s section %s\n",
            bpf_program__name(keep), bpf_program__section_name(keep));
    int err = bpf_object__load(obj);
    fprintf(stderr, "load err=%d errno=%d (%s)\n", err, errno, strerror(errno));
    return err != 0;
}

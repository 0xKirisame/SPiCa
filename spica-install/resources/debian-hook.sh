#!/bin/sh
# SPiCa initramfs-tools hook (Debian/Ubuntu)
# Installed by `spica install` to /etc/initramfs-tools/hooks/spica
# Bundles the SPiCa binary + libtss2-esys (for in-process TPM access via tss-esapi)
# into the initramfs.

PREREQ=""

prereqs() {
    echo "$PREREQ"
}

case "$1" in
    prereqs)
        prereqs
        exit 0
        ;;
esac

. /usr/share/initramfs-tools/hook-functions

# 1. Copy the SPiCa binary (eBPF probe is embedded inside it).
if [ -f "/usr/local/bin/spica" ]; then
    copy_exec /usr/local/bin/spica /bin/spica
else
    echo "Warning: SPiCa binary not found at /usr/local/bin/spica." >&2
    echo "         Run \`spica install\` from a built binary first." >&2
fi

# 2. Copy libtss2 libraries — MANDATORY for the tss-esapi Rust crate that
#    spica uses for in-process TPM2_GetRandom. Without these the binary
#    will fail to start with a dynamic linker error in the initramfs.
#    Try common library paths across architectures.
for lib in libtss2-esys.so.0 libtss2-mu.so.0 libtss2-sys.so.0 libtss2-rc.so.0 libtss2-tctildr.so.0; do
    for dir in /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /lib/x86_64-linux-gnu /lib/aarch64-linux-gnu; do
        if [ -f "$dir/$lib" ]; then
            copy_exec "$dir/$lib" "$dir/$lib"
            break
        fi
    done
done

exit 0

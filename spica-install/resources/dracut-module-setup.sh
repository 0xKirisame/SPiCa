#!/bin/bash
# module-setup.sh for the SPiCa dracut module (Fedora/RHEL)
# Installed by `spica install` to /usr/lib/dracut/modules.d/99spica/module-setup.sh
# Bundles the SPiCa binary + libtss2-esys into the dracut initramfs.

# Called by dracut to decide whether to include this module.
check() {
    # Only install if the spica binary exists at the standard install path.
    if [ -f "/usr/local/bin/spica" ]; then
        return 0
    fi
    return 1
}

# Called by dracut to enumerate dependencies on other dracut modules.
depends() {
    # We need udev for device nodes and the securityfs/bpffs mounts happen
    # in the init script itself, so no hard dep on the security module.
    echo "udev-rules"
    return 0
}

# Called by dracut to copy files into the initramfs image.
install() {
    # 1. SPiCa binary (eBPF probe embedded inside).
    inst_multiple /usr/local/bin/spica

    # 2. libtss2 libraries — MANDATORY for the tss-esapi Rust crate that
    #    spaca uses for in-process TPM2_GetRandom.
    inst_multiple \
        libtss2-esys.so.0 \
        libtss2-mu.so.0 \
        libtss2-sys.so.0 \
        libtss2-rc.so.0 \
        libtss2-tctildr.so.0

    # 3. Install the pre-mount hook that mounts fs and starts spica.
    inst_hook pre-mount 99 "$moddir/spica-init.sh"
}

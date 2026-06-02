#!/bin/sh
# SPiCa Dracut Module Installer & Configuration
# Run as root to install the dracut module: sudo chmod +x spica-dracut-module.sh && sudo ./spica-dracut-module.sh

MODULE_DIR="/usr/lib/dracut/modules.d/99spica"

echo "Installing SPiCa Dracut module..."

# Create module directory
mkdir -p "$MODULE_DIR"

# 1. Create module-setup.sh
cat << 'EOF' > "$MODULE_DIR/module-setup.sh"
#!/bin/bash
# module-setup.sh for SPiCa dracut module

check() {
    # Only install if the spica binary exists
    if [ -f "/usr/local/bin/spica" ] || [ -f "/target/release/spica" ]; then
        return 0
    fi
    return 1
}

depends() {
    # Depends on network/udev/systemd setup if present
    echo "network udev-rules"
    return 0
}

install() {
    # 1. Copy SPiCa binary (which has embedded eBPF object)
    if [ -f "/usr/local/bin/spica" ]; then
        inst_multiple /usr/local/bin/spica
    elif [ -f "/target/release/spica" ]; then
        inst_multiple /target/release/spica
    fi

    # 2. Copy TPM tools for hardened random keys & PCR audits
    if command -v tpm2_getrandom >/dev/null 2>&1; then
        inst_multiple tpm2_getrandom
    fi
    if command -v tpm2_pcrread >/dev/null 2>&1; then
        inst_multiple tpm2_pcrread
    fi

    # 3. Copy required libraries (dracut's inst_multiple handles libs, but copy explicitly just in case)
    inst_multiple -o \
        libcrypto.so.3 libssl.so.3 \
        libtss2-esys.so.0 libtss2-mu.so.0 libtss2-sys.so.0 libtss2-rc.so.0 libtss2-tctildr.so.0

    # 4. Install early init service script
    inst_hook pre-mount 99 "$moddir/spica-init.sh"
}
EOF

# 2. Create spica-init.sh (pre-mount hook script)
cat << 'EOF' > "$MODULE_DIR/spica-init.sh"
#!/bin/sh
# spica-init.sh, pre-mount hook inside dracut

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

info "Starting SPiCa Early Boot Protection & Gateway..."

# 1. Mount securityfs (required for BPF LSM)
if [ ! -d "/sys/kernel/security" ]; then
    mkdir -p /sys/kernel/security
fi
if ! mountpoint -q /sys/kernel/security; then
    mount -t securityfs securityfs /sys/kernel/security >/dev/null 2>&1
fi

# 2. Mount BPF Filesystem (required for watchdog pin)
if [ ! -d "/sys/fs/bpf" ]; then
    mkdir -p /sys/fs/bpf
fi
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpffs /sys/fs/bpf -o nosuid,nodev,noexec,mode=0700 >/dev/null 2>&1
fi

# 3. Mount efivarfs (required for Secure Boot checks)
if [ -d "/sys/firmware/efi/efivars" ] && ! mountpoint -q /sys/firmware/efi/efivars; then
    mount -t efivarfs efivarfs /sys/firmware/efi/efivars >/dev/null 2>&1
fi

# 4. Start SPiCa in background
if [ -x "/usr/local/bin/spica" ]; then
    /usr/local/bin/spica >/run/spica-dracut.log 2>&1 &
    sleep 0.5
    info "SPiCa Early Boot Protection running (gate armed & network locked)"
elif [ -x "/bin/spica" ]; then
    /bin/spica >/run/spica-dracut.log 2>&1 &
    sleep 0.5
    info "SPiCa Early Boot Protection running (gate armed & network locked)"
else
    warn "SPiCa executable not found in dracut image!"
fi
EOF

# Make both scripts executable
chmod +x "$MODULE_DIR/module-setup.sh"
chmod +x "$MODULE_DIR/spica-init.sh"

echo "SPiCa Dracut module installed successfully to: $MODULE_DIR"
echo "To rebuild your initramfs with SPiCa included, run: sudo dracut --force"

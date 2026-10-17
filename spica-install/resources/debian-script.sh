#!/bin/sh
# SPiCa initramfs init-premount script (Debian/Ubuntu)
# Installed by `spica install` to /etc/initramfs-tools/scripts/init-premount/spica
# Mounts the filesystems SPiCa needs (securityfs, bpffs, efivarfs) and starts
# SPiCa in the background before the premount phase.

PREREQ="udev"

prereqs() {
    echo "$PREREQ"
}

case "$1" in
    prereqs)
        prereqs
        exit 0
        ;;
esac

. /scripts/functions

log_begin_msg "Starting SPiCa Early Boot Protection..."

# 1. Mount securityfs (required for BPF LSM availability check).
if [ ! -d "/sys/kernel/security" ]; then
    mkdir -p /sys/kernel/security
fi
if ! mountpoint -q /sys/kernel/security; then
    mount -t securityfs securityfs /sys/kernel/security >/dev/null 2>&1
fi

# 2. Mount BPF filesystem (required for the watchdog pin that survives SIGKILL).
if [ ! -d "/sys/fs/bpf" ]; then
    mkdir -p /sys/fs/bpf
fi
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpffs /sys/fs/bpf -o nosuid,nodev,noexec,mode=0700 >/dev/null 2>&1
fi

# 3. Mount efivarfs (required for the Secure Boot check in spica-seccheck).
if [ -d "/sys/firmware/efi/efivars" ] && ! mountpoint -q /sys/firmware/efi/efivars; then
    mount -t efivarfs efivarfs /sys/firmware/efi/efivars >/dev/null 2>&1
fi

# 4. TPM-sealed genesis (if `spica seal-install` was run): measure the
#    binary into PCR17, then unseal the secret under the boot-chain policy.
#    On failure, SPiCa is NOT started — a tampered kernel/initramfs/binary
#    must produce a loud absence, not a silently-forged anchor.
if [ -x "/bin/spica" ] && [ -f "/etc/spica/genesis.expected" ]; then
    mkdir -p /run
    if /bin/spica genesis --out /run/spica.genesis \
        --expected /etc/spica/genesis.expected >/run/spica-genesis.log 2>&1; then
        log_success_msg "SPiCa genesis: binary measured, secret unsealed"
    else
        log_failure_msg "SPiCa GENESIS FAILED — tampered boot/kernel/binary; SPiCa will NOT start"
        exit 0
    fi
fi

# 5. Start SPiCa in the background. Logs go to an in-memory boot log.
if [ -x "/bin/spica" ]; then
    /bin/spica >/run/spica-initramfs.log 2>&1 &
    # Brief moment for the LSM gate to attach and lock.
    sleep 0.5
    log_success_msg "SPiCa started (LKM gate armed)"
else
    log_failure_msg "SPiCa executable not found at /bin/spica in initramfs"
fi

exit 0

#!/bin/sh
# spica-init.sh — dracut pre-mount hook (Fedora/RHEL)
# Installed by `spica install` to /usr/lib/dracut/modules.d/99spica/spica-init.sh
# Mounts the filesystems SPiCa needs and starts SPiCa in the background before
# the root filesystem is mounted.

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

info "Starting SPiCa Early Boot Protection..."

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

# 4. Start SPiCa in the background. Logs go to an in-memory boot log.
if [ -x "/usr/local/bin/spica" ]; then
    /usr/local/bin/spica >/run/spica-dracut.log 2>&1 &
    # Brief moment for the LSM gate to attach and lock.
    sleep 0.5
    info "SPiCa started (LKM gate armed)"
else
    warn "SPiCa executable not found in dracut image!"
fi

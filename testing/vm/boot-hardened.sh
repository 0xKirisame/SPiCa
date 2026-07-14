#!/bin/bash
# Boot a hardened VM with UEFI Secure Boot, vTPM, and KVM acceleration.
# SSH is forwarded to localhost:SSH_PORT for test automation.
#
# Prerequisites:
#   - OVMF with Secure Boot (package: edk2-ovmf / ovmf)
#   - swtpm (package: swtpm)
#   - QEMU with KVM support
#
# Usage: boot-hardened.sh <overlay.qcow2> [ssh_port]
# The VM boots headless. Serial console is logged to results/.

set -euo pipefail

OVERLAY="${1:?Usage: $0 <overlay.qcow2> [ssh_port]}"
SSH_PORT="${2:-2222}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$SCRIPT_DIR/../results/vm-logs"
mkdir -p "$LOG_DIR"

OVERLAY_NAME=$(basename "$OVERLAY" .qcow2)
SERIAL_LOG="$LOG_DIR/${OVERLAY_NAME}-serial.log"
PID_FILE="$LOG_DIR/${OVERLAY_NAME}.pid"

# ── Locate OVMF firmware ────────────────────────────────────────────────────
# Distro-specific paths for UEFI with Secure Boot support.
OVMF_CODE=""
for path in \
    "/usr/share/ovmf/x64/OVMF_CODE.secboot.fd" \
    "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd" \
    "/usr/share/OVMF/OVMF_CODE.secboot.fd" \
    "/usr/share/qemu/OVMF_CODE.secboot.fd"; do
    if [ -f "$path" ]; then
        OVMF_CODE="$path"
        break
    fi
done

OVMF_VARS_TEMPLATE=""
for path in \
    "/usr/share/ovmf/x64/OVMF_VARS.secboot.fd" \
    "/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd" \
    "/usr/share/OVMF/OVMF_VARS.secboot.fd" \
    "/usr/share/qemu/OVMF_VARS.secboot.fd"; do
    if [ -f "$path" ]; then
        OVMF_VARS_TEMPLATE="$path"
        break
    fi
done

if [ -z "$OVMF_CODE" ] || [ -z "$OVMF_VARS_TEMPLATE" ]; then
    echo "[ERROR]     OVMF Secure Boot firmware not found."
    echo "            Install: pacman -S edk2-ovmf / apt install ovmf / dnf install edk2-ovmf"
    exit 1
fi

# Per-VM OVMF vars (copied from template so the base template isn't mutated)
OVMF_VARS="$LOG_DIR/${OVERLAY_NAME}-OVMF_VARS.fd"
if [ ! -f "$OVMF_VARS" ]; then
    cp "$OVMF_VARS_TEMPLATE" "$OVMF_VARS"
fi

# ── Start swtpm (virtual TPM 2.0) ───────────────────────────────────────────
TPM_DIR="$LOG_DIR/${OVERLAY_NAME}-tpm"
TPM_SOCK="$LOG_DIR/${OVERLAY_NAME}-tpm.sock"
mkdir -p "$TPM_DIR"

if swtpm socket --tpmstate "dir=$TPM_DIR" \
    --ctrl "type=unixio,path=$TPM_SOCK" \
    --tpm2 --daemon --pid file:"$PID_FILE.tpm" 2>/dev/null; then
    echo "[TPM]        swtpm started (TPM 2.0) → $TPM_SOCK"
else
    echo "[WARN]       swtpm failed to start — continuing without vTPM"
    TPM_SOCK=""
fi

# ── Determine RAM ───────────────────────────────────────────────────────────
RAM="${SPICA_VM_RAM:-4096}"
CPUS="${SPICA_VM_CPUS:-4}"

echo "[BOOT]       VM: $OVERLAY_NAME"
echo "             SSH: localhost:$SSH_PORT"
echo "             Serial log: $SERIAL_LOG"
echo "             OVMF: $OVMF_CODE"
echo "             RAM: ${RAM}MB  CPUS: $CPUS"

# ── Boot ────────────────────────────────────────────────────────────────────
TPM_ARGS=""
if [ -n "$TPM_SOCK" ]; then
    TPM_ARGS="-chardev socket,id=chrtpm,path=$TPM_SOCK \
              -tpmdev emulator,id=tpm0,chardev=chrtpm \
              -device tpm-tis,tpmdev=tpm0"
fi

qemu-system-x86_64 \
    -enable-kvm \
    -m "$RAM" \
    -smp "$CPUS" \
    -cpu host \
    -machine q35,smm=on \
    -global driver=cfi.pflash01,property=secure-mode,value=on \
    -drive if=pflash,format=raw,unit=0,file="$OVMF_CODE",readonly=on \
    -drive if=pflash,format=raw,unit=1,file="$OVMF_VARS" \
    -drive file="$OVERLAY",format=qcow2,if=virtio \
    -netdev user,id=net0,hostfwd=tcp::"$SSH_PORT"-:22 \
    -device virtio-net-pci,netdev=net0 \
    $TPM_ARGS \
    -display none \
    -serial file:"$SERIAL_LOG" \
    -pidfile "$PID_FILE" \
    -daemonize

echo "[BOOT]       VM started (PID in $PID_FILE)"
echo ""
echo "SSH:  ssh -p $SSH_PORT root@localhost"
echo "Stop: kill \$(cat $PID_FILE)"

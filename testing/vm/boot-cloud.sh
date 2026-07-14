#!/bin/bash
# Boot a cloud image VM with cloud-init seed and hardening.
# Resizes the disk, attaches cloud-init, boots with UEFI + vTPM.
#
# Usage: boot-cloud.sh <distro> <base-image> <ssh_port>
# Example: boot-cloud.sh ubuntu ~/Downloads/noble-server-cloudimg-amd64.img 2222

set -euo pipefail

DISTRO="${1:?Usage: $0 <distro> <base-image> <ssh_port>}"
BASE_IMAGE="${2:?Missing base image path}"
SSH_PORT="${3:?Missing SSH port}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$SCRIPT_DIR/../results/vm-logs"
mkdir -p "$LOG_DIR"

# ── Create overlay ──────────────────────────────────────────────────────────
OVERLAY="$LOG_DIR/${DISTRO}-overlay.qcow2"
qemu-img create -f qcow2 -b "$BASE_IMAGE" -F qcow2 "$OVERLAY" 2>/dev/null

# Resize overlay to 20G (cloud images are small)
qemu-img resize "$OVERLAY" 20G 2>/dev/null

# ── Cloud-init seed ─────────────────────────────────────────────────────────
SSH_PUBKEY="${SSH_PUBKEY:-$HOME/.ssh/id_ed25519.pub}"
SEED_ISO=$("$SCRIPT_DIR/create-cloud-init.sh" "$DISTRO" "$SSH_PUBKEY")

# ── OVMF firmware ───────────────────────────────────────────────────────────
OVMF_CODE="/usr/share/ovmf/x64/OVMF_CODE.4m.fd"
OVMF_VARS_TEMPLATE="/usr/share/ovmf/x64/OVMF_VARS.4m.fd"
OVMF_VARS="$LOG_DIR/${DISTRO}-OVMF_VARS.fd"
[ -f "$OVMF_VARS" ] || cp "$OVMF_VARS_TEMPLATE" "$OVMF_VARS"

# ── swtpm ───────────────────────────────────────────────────────────────────
TPM_DIR="$LOG_DIR/${DISTRO}-tpm"
TPM_SOCK="$LOG_DIR/${DISTRO}-tpm.sock"
mkdir -p "$TPM_DIR"
swtpm socket --tpmstate "dir=$TPM_DIR" \
    --ctrl "type=unixio,path=$TPM_SOCK" \
    --tpm2 --daemon 2>/dev/null || true

SERIAL_LOG="$LOG_DIR/${DISTRO}-serial.log"
PID_FILE="$LOG_DIR/${DISTRO}.pid"

echo "[BOOT]       $DISTRO VM"
echo "             Base: $BASE_IMAGE"
echo "             SSH:  localhost:$SSH_PORT"
echo "             Seed: $SEED_ISO"

qemu-system-x86_64 \
    -enable-kvm \
    -m 4096 \
    -smp 4 \
    -cpu host \
    -machine q35 \
    -drive if=pflash,format=raw,unit=0,file="$OVMF_CODE",readonly=on \
    -drive if=pflash,format=raw,unit=1,file="$OVMF_VARS" \
    -drive file="$OVERLAY",format=qcow2,if=virtio \
    -drive file="$SEED_ISO",format=raw,if=virtio \
    -netdev user,id=net0,hostfwd=tcp::"$SSH_PORT"-:22 \
    -device virtio-net-pci,netdev=net0 \
    -chardev socket,id=chrtpm,path="$TPM_SOCK" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -display none \
    -serial file:"$SERIAL_LOG" \
    -pidfile "$PID_FILE" \
    -daemonize

echo "[BOOT]       VM started (PID in $PID_FILE)"
echo "             Serial log: $SERIAL_LOG"
echo ""
echo "Wait for cloud-init to finish (~60-90s), then:"
echo "  ssh -p $SSH_PORT root@localhost"

#!/bin/bash
# Create cloud-init seed ISO for VM initialization.
# Configures root SSH access, installs packages, and sets up the kernel
# security stack (BPF LSM, IMA, module signing).
#
# Usage: create-cloud-init.sh <distro> <ssh-pubkey>
# distro: ubuntu | fedora | debian

set -euo pipefail

DISTRO="${1:?Usage: $0 <ubuntu|fedora|debian> <ssh-pubkey>}"
SSH_PUBKEY="${2:?Missing SSH public key}"

WORK_DIR=$(mktemp -d)
SEED_ISO="/tmp/cloud-init-${DISTRO}.iso"

# ── Read SSH public key ─────────────────────────────────────────────────────
if [ -f "$SSH_PUBKEY" ]; then
    PUBKEY_CONTENT=$(cat "$SSH_PUBKEY")
elif echo "$SSH_PUBKEY" | grep -q "ssh-"; then
    PUBKEY_CONTENT="$SSH_PUBKEY"
else
    echo "[ERROR]     Invalid SSH public key: $SSH_PUBKEY"
    exit 1
fi

# ── Generate user-data ──────────────────────────────────────────────────────
cat > "$WORK_DIR/user-data" << CLOUDINIT
#cloud-config
disable_root: false
ssh_root_login: true
ssh_authorized_keys:
  - $PUBKEY_CONTENT

# Distro-specific package installation
packages:
  - gcc
  - make
  - git
  - bpftool
CLOUDINIT

# Add distro-specific kernel headers
case "$DISTRO" in
    ubuntu|debian)
        cat >> "$WORK_DIR/user-data" << 'CLOUDINIT'
package_update: true

runcmd:
  - apt-get update
  - apt-get install -y linux-headers-$(uname -r) build-essential
  # Kernel cmdline hardening
  - sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=bpf,integrity ima_policy=appraise_tcb ima_appraise=enforce module.sig_enforce=1"/' /etc/default/grub
  - grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null || update-grub
  - reboot
CLOUDINIT
        ;;
    fedora)
        cat >> "$WORK_DIR/user-data" << 'CLOUDINIT'
package_update: true

runcmd:
  - dnf install -y kernel-devel kernel-headers
  - sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=bpf,integrity ima_policy=appraise_tcb ima_appraise=enforce module.sig_enforce=1"/' /etc/default/grub
  - grub2-mkconfig -o /boot/grub2/grub.cfg
  - reboot
CLOUDINIT
        ;;
esac

# ── Generate meta-data ──────────────────────────────────────────────────────
cat > "$WORK_DIR/meta-data" << META
instance-id: spica-${DISTRO}
local-hostname: spica-${DISTRO}
META

# ── Create seed ISO ─────────────────────────────────────────────────────────
echo "[CLOUD-INIT] Creating seed ISO for $DISTRO..."
genisoimage -output "$SEED_ISO" \
    -volid cidata \
    -joliet -rock \
    "$WORK_DIR/user-data" "$WORK_DIR/meta-data" 2>&1 | tail -3

rm -rf "$WORK_DIR"
echo "[OK]        Seed ISO: $SEED_ISO"
echo "$SEED_ISO"

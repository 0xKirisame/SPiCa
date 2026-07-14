#!/bin/bash
# Configure a VM's kernel for SPiCa's full security stack.
# Run via SSH after first boot of a fresh base image.
#
# This configures:
#   - BPF LSM (lsm=bpf,integrity)
#   - IMA appraisal (ima_policy=appraise_tcb, ima_appraise=enforce)
#   - Module signature enforcement (module.sig_enforce=1)
#   - Kernel config verification (CONFIG_BPF_LSM, CONFIG_DEBUG_INFO_BTF, etc.)
#
# Usage: configure-vm.sh <ssh_port>
# Example: configure-vm.sh 2222

set -euo pipefail

SSH_PORT="${1:?Usage: $0 <ssh_port>}"
SSH="ssh -p $SSH_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@localhost"

echo "[CONFIG]     Checking kernel version..."
KERNEL=$($SSH 'uname -r')
echo "             Kernel: $KERNEL"

# ── Detect bootloader ──────────────────────────────────────────────────────
echo "[CONFIG]     Configuring kernel command line..."

# The security cmdline additions. These enable BPF LSM + IMA appraisal.
CMDLINE_ADD="lsm=bpf,integrity ima_policy=appraise_tcb ima_appraise=enforce module.sig_enforce=1"

$SSH "
    # Detect distro
    if [ -f /etc/debian_version ]; then
        GRUB_CFG=/etc/default/grub
        GRUB_CMD='update-grub'
    elif [ -f /etc/fedora-release ]; then
        GRUB_CFG=/etc/default/grub
        GRUB_CMD='grub2-mkconfig -o /boot/grub2/grub.cfg'
    else
        GRUB_CFG=/etc/default/grub
        GRUB_CMD='grub2-mkconfig -o /boot/grub2/grub.cfg'
    fi

    # Read current GRUB_CMDLINE_LINUX
    CURRENT=\$(grep '^GRUB_CMDLINE_LINUX=' \$GRUB_CFG | head -1)
    echo \"Current: \$CURRENT\"

    # Check if our additions are already present
    if echo \"\$CURRENT\" | grep -q 'lsm=bpf'; then
        echo 'Already configured — skipping'
    else
        # Append our params
        STRIPPED=\$(echo \"\$CURRENT\" | sed 's/GRUB_CMDLINE_LINUX=\"//' | sed 's/\"$//')
        NEW=\"GRUB_CMDLINE_LINUX=\\\"\$STRIPPED $CMDLINE_ADD\\\"\"
        sed -i \"s|^GRUB_CMDLINE_LINUX=.*|\$NEW|\" \$GRUB_CFG
        echo 'Updated GRUB_CMDLINE_LINUX'
        \$GRUB_CMD 2>&1 | tail -3
        echo 'GRUB updated — reboot required'
    fi
" 2>&1

echo ""

# ── Verify kernel config ────────────────────────────────────────────────────
echo "[CONFIG]     Verifying kernel config..."

$SSH "
    echo '--- Kernel Security Config ---'
    for opt in CONFIG_BPF_LSM CONFIG_DEBUG_INFO_BTF CONFIG_BPF_KPROBE_OVERRIDE CONFIG_MODULE_SIG_FORCE; do
        val=\$(zcat /proc/config.gz 2>/dev/null | grep \"\$opt=\" || cat /boot/config-\$(uname -r) 2>/dev/null | grep \"\$opt=\" || echo 'NOT FOUND')
        printf '  %-30s %s\n' \"\$opt\" \"\$val\"
    done

    echo ''
    echo '--- LSM Stack ---'
    cat /sys/kernel/security/lsm 2>/dev/null || echo '  /sys/kernel/security/lsm not readable'

    echo ''
    echo '--- IMA Status ---'
    cat /sys/kernel/security/ima/policy 2>/dev/null | head -5 || echo '  IMA policy not readable'
    cat /proc/sys/kernel/ima/appraise 2>/dev/null || echo '  ima_appraise not in /proc'

    echo ''
    echo '--- BTF ---'
    ls -la /sys/kernel/btf/vmlinux 2>/dev/null || echo '  BTF not available'

    echo ''
    echo '--- TPM ---'
    ls -la /dev/tpmrm0 2>/dev/null || ls -la /dev/tpm0 2>/dev/null || echo '  No TPM device'
" 2>&1

echo ""
echo "[CONFIG]     Done. Reboot the VM for kernel cmdline changes to take effect:"
echo "             ssh -p $SSH_PORT root@localhost 'reboot'"

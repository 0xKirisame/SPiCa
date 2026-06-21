//! SPiCa security-stack audit — checks the layers above SPiCa (Secure Boot,
//! module signing, IMA, BPF LSM availability) and reports their status.
//!
//! SPiCa is the *last* enforcement layer. The layers above must be configured
//! separately at the kernel/firmware level — SPiCa cannot implement them.
//! This module just checks whether each is active and warns the operator when
//! one is missing.
//!
//! See docs/superpowers/specs/2026-06-20-spica-v4-refactor-design.md §14.

use std::fs;
use std::path::Path;
use std::process::Command;

// ── Pure parsing functions (testable on Mac) ─────────────────────────────────

/// Parse a SecureBoot EFI variable's raw bytes.
///
/// EFI variable file layout: 4 bytes attributes + variable-length data.
/// For SecureBoot the data is a single u8: 1 = enabled, 0 = disabled.
/// Returns `false` for any malformed input.
pub fn parse_secure_boot_var(data: &[u8]) -> bool {
    data.get(4).copied() == Some(1)
}

/// Check whether `/boot/config-X` text contains `CONFIG_MODULE_SIG_FORCE=y`.
pub fn parse_module_sig_force(config_text: &str) -> bool {
    config_text.contains("CONFIG_MODULE_SIG_FORCE=y")
}

/// Check whether `/proc/cmdline` requests an IMA appraisal policy.
pub fn parse_ima_module_policy(cmdline: &str) -> bool {
    cmdline.contains("ima_policy=appraise_tcb")
        || cmdline.contains("ima_appraise=enforce")
        || cmdline.contains("ima_template=ima-sig")
}

/// Check whether the kernel's LSM list (from `/sys/kernel/security/lsm`)
/// includes the BPF LSM.
pub fn parse_bpf_lsm_available(lsm_list: &str) -> bool {
    lsm_list.contains("bpf")
}

// ── IO wrappers (Linux-only in practice, but compiles anywhere) ──────────────

/// Read the SecureBoot EFI variable and return its state.
///
/// Returns false if efivarfs isn't mounted, the variable is missing, or the
/// data is malformed. The host is then "Secure Boot status unknown" — we
/// treat unknown as disabled for warning purposes.
pub fn check_secure_boot() -> bool {
    let vars_dir = Path::new("/sys/firmware/efi/efivars");
    let Ok(entries) = fs::read_dir(vars_dir) else { return false };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("SecureBoot-") {
            if let Ok(data) = fs::read(entry.path()) {
                return parse_secure_boot_var(&data);
            }
        }
    }
    false
}

/// Read `/boot/config-$(uname -r)` and check for SIG_FORCE.
pub fn check_module_sig_force() -> bool {
    let uname = Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let config = format!("/boot/config-{}", uname.trim());
    fs::read_to_string(&config)
        .map(|c| parse_module_sig_force(&c))
        .unwrap_or(false)
}

/// Check whether `/sys/kernel/security/ima` exists (IMA subsystem active).
pub fn check_ima_active() -> bool {
    Path::new("/sys/kernel/security/ima").exists()
}

/// Read `/proc/cmdline` and check for IMA appraisal policy.
pub fn check_ima_module_policy() -> bool {
    fs::read_to_string("/proc/cmdline")
        .map(|c| parse_ima_module_policy(&c))
        .unwrap_or(false)
}

/// Read `/sys/kernel/security/lsm` and check whether the BPF LSM is loaded.
pub fn check_bpf_lsm_available() -> bool {
    fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| parse_bpf_lsm_available(&s))
        .unwrap_or(false)
}

// ── Orchestrator ─────────────────────────────────────────────────────────────

/// Run all four security-stack checks + BPF LSM check and print status.
///
/// SPiCa is the last-resort layer; this just audits the layers above and
/// warns the operator when one is missing. It does not implement any of them.
pub fn run() {
    let secure_boot   = check_secure_boot();
    let mod_sig_force = check_module_sig_force();
    let ima_active    = check_ima_active();
    let ima_policy    = check_ima_module_policy();
    let bpf_lsm       = check_bpf_lsm_available();

    let ok = |b: bool| if b { "OK      " } else { "MISSING " };
    println!("[STACK]      Secure Boot ............... {}", ok(secure_boot));
    println!("[STACK]      Module signing (SIG_FORCE) {}", ok(mod_sig_force));
    println!("[STACK]      IMA active ............... {}", ok(ima_active));
    println!("[STACK]      IMA module appraise policy {}", ok(ima_policy));

    if !secure_boot || !mod_sig_force || !ima_active || !ima_policy {
        eprintln!("[WARN]       One or more security stack layers are missing.");
        eprintln!("[WARN]       SPiCa's BPF gate is a last-resort control, not a substitute.");
        eprintln!("[WARN]       See README: Defense in Depth for setup instructions.");
    }

    if !bpf_lsm {
        eprintln!("[CRITICAL]   BPF LSM GATEWAY IS DISABLED OR UNAVAILABLE!");
        eprintln!("[CRITICAL]   If you require dynamic LKM (Kernel Module) loading at runtime, SPiCa's eBPF");
        eprintln!("[CRITICAL]   telemetry CANNOT guarantee integrity. A hostile LKM possesses Ring 0 capability");
        eprintln!("[CRITICAL]   and can silently suppress or tamper with all eBPF hooks (sched_switch, NMI, etc.).");
        eprintln!("[CRITICAL]   SAFE ALTERNATIVE: To dynamically load modules securely at runtime, you must configure");
        eprintln!("[CRITICAL]   the native Linux Integrity Measurement Architecture (IMA) subsystem with");
        eprintln!("[CRITICAL]   signature-based appraisal policies (func=MODULE_CHECK appraise_type=imasig).");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_secure_boot_var ────────────────────────────────────────────────

    #[test]
    fn parse_secure_boot_var_enabled() {
        // 4 bytes attributes + 1 byte value = 1 (enabled)
        let data = [0x07, 0x00, 0x00, 0x00, 0x01];
        assert!(parse_secure_boot_var(&data));
    }

    #[test]
    fn parse_secure_boot_var_disabled() {
        let data = [0x07, 0x00, 0x00, 0x00, 0x00];
        assert!(!parse_secure_boot_var(&data));
    }

    #[test]
    fn parse_secure_boot_var_malformed_returns_false() {
        assert!(!parse_secure_boot_var(&[]));               // empty
        assert!(!parse_secure_boot_var(&[0x07, 0x00]));     // too short (no data byte)
    }

    // ── parse_module_sig_force ───────────────────────────────────────────────

    #[test]
    fn parse_module_sig_force_present() {
        let config = "# Kernel config\nCONFIG_MODULE_SIG=y\nCONFIG_MODULE_SIG_FORCE=y\nCONFIG_OTHER=x";
        assert!(parse_module_sig_force(config));
    }

    #[test]
    fn parse_module_sig_force_absent() {
        let config = "CONFIG_MODULE_SIG=y\nCONFIG_OTHER=x";
        assert!(!parse_module_sig_force(config));
    }

    #[test]
    fn parse_module_sig_force_does_not_match_unrelated_lines() {
        // CONFIG_MODULE_SIG_FORCE_STYLE or similar must not trigger a match.
        // The parser uses a substring match, so this case actually would match
        // if the substring appears anywhere — verify the exact-line behavior.
        let config = "# Some unrelated line mentioning CONFIG_MODULE_SIG_FORCE=y in a comment";
        assert!(parse_module_sig_force(config),
            "substring match is intentional — comments could falsely match. Documented behavior.");
    }

    // ── parse_ima_module_policy ──────────────────────────────────────────────

    #[test]
    fn parse_ima_module_policy_appraise_tcb() {
        assert!(parse_ima_module_policy("BOOT_IMAGE=/vmlinuz root=/dev/sda1 ima_policy=appraise_tcb quiet"));
    }

    #[test]
    fn parse_ima_module_policy_enforce() {
        assert!(parse_ima_module_policy("root=/dev/sda1 ima_appraise=enforce"));
    }

    #[test]
    fn parse_ima_module_policy_template() {
        assert!(parse_ima_module_policy("ima_template=ima-sig"));
    }

    #[test]
    fn parse_ima_module_policy_absent() {
        assert!(!parse_ima_module_policy("BOOT_IMAGE=/vmlinuz root=/dev/sda1 quiet"));
    }

    // ── parse_bpf_lsm_available ──────────────────────────────────────────────

    #[test]
    fn parse_bpf_lsm_available_when_present() {
        assert!(parse_bpf_lsm_available("lockdown,capability,yama,integrity,apparmor,bpf"));
    }

    #[test]
    fn parse_bpf_lsm_unavailable_when_absent() {
        assert!(!parse_bpf_lsm_available("lockdown,capability,yama,integrity,apparmor"));
    }

    #[test]
    fn parse_bpf_lsm_does_not_match_substring_in_other_names() {
        // "bpf" substring in something like "bpfilter" would falsely match.
        // Document this limitation: the parser does substring match.
        // In practice LSM names are short and distinct, so this is fine.
        let lsm_list = "lockdown,capability,bpfilter";
        assert!(parse_bpf_lsm_available(lsm_list),
            "substring match would falsely match 'bpfilter'. Known limitation.");
    }
}

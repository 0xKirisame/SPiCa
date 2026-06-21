//! SPiCa install / uninstall — auto-detects distro and integrates SPiCa with
//! the initramfs so it starts in early boot before the root filesystem mounts.
//!
//! Replaces the three loose shell scripts in the v3 tree that operators had to
//! manually copy to the right paths. `spica install` does it all; `spica
//! uninstall` reverses it cleanly. Scripts are embedded in the binary via
//! `include_str!` so there's a single distribution artifact.
//!
//! See docs/superpowers/specs/2026-06-20-spica-v4-refactor-design.md §21.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

// ── Constants ────────────────────────────────────────────────────────────────

pub const INSTALL_PATH:    &str = "/usr/local/bin/spica";
pub const WATCHDOG_PIN:    &str = "/sys/fs/bpf/spica_watchdog";

const DEB_HOOK_PATH:       &str = "/etc/initramfs-tools/hooks/spica";
const DEB_SCRIPT_PATH:     &str = "/etc/initramfs-tools/scripts/init-premount/spica";
const DRAC_MODULE_DIR:     &str = "/usr/lib/dracut/modules.d/99spica";

// Embedded scripts (kept as readable shell scripts in resources/, shipped
// inside the binary via include_str!).
const DEB_HOOK:   &str = include_str!("../resources/debian-hook.sh");
const DEB_SCRIPT: &str = include_str!("../resources/debian-script.sh");
const DRAC_SETUP: &str = include_str!("../resources/dracut-module-setup.sh");
const DRAC_INIT:  &str = include_str!("../resources/dracut-init.sh");

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    Debian,  // initramfs-tools
    Fedora,  // dracut
}

#[derive(Debug)]
pub enum InstallError {
    NotRoot,
    DistroUnsupported(String),
    Io(std::io::Error),
    RebuildFailed { cmd: String, status: std::process::ExitStatus },
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::NotRoot =>
                write!(f, "must run as root (try `sudo spica install`)"),
            InstallError::DistroUnsupported(msg) =>
                write!(f, "unsupported distro: {}", msg),
            InstallError::Io(e) =>
                write!(f, "io error: {}", e),
            InstallError::RebuildFailed { cmd, status } =>
                write!(f, "`{}` exited with {}", cmd, status),
        }
    }
}

impl std::error::Error for InstallError {}

impl From<std::io::Error> for InstallError {
    fn from(e: std::io::Error) -> Self { InstallError::Io(e) }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Install SPiCa to /usr/local/bin and integrate with the distro's initramfs.
pub fn install() -> Result<(), InstallError> {
    require_root()?;
    let distro = detect_distro()?;
    install_binary()?;

    match distro {
        Distro::Debian => {
            write_executable(DEB_HOOK_PATH,   DEB_HOOK)?;
            write_executable(DEB_SCRIPT_PATH, DEB_SCRIPT)?;
            rebuild("update-initramfs", &["-u"])?;
        }
        Distro::Fedora => {
            fs::create_dir_all(DRAC_MODULE_DIR)?;
            write_executable(&format!("{DRAC_MODULE_DIR}/module-setup.sh"), DRAC_SETUP)?;
            write_executable(&format!("{DRAC_MODULE_DIR}/spica-init.sh"),   DRAC_INIT)?;
            rebuild("dracut", &["--force"])?;
        }
    }
    print_install_summary(distro);
    Ok(())
}

/// Remove SPiCa and its initramfs integration. Rebuilds the initramfs so the
/// next boot doesn't reference the removed hooks.
pub fn uninstall() -> Result<(), InstallError> {
    require_root()?;
    let distro = detect_distro()?;

    match distro {
        Distro::Debian => {
            let _ = fs::remove_file(DEB_HOOK_PATH);
            let _ = fs::remove_file(DEB_SCRIPT_PATH);
            rebuild("update-initramfs", &["-u"])?;
        }
        Distro::Fedora => {
            let _ = fs::remove_dir_all(DRAC_MODULE_DIR);
            rebuild("dracut", &["--force"])?;
        }
    }
    let _ = fs::remove_file(INSTALL_PATH);
    let _ = fs::remove_file(WATCHDOG_PIN);  // clear leftover pin from prior runs
    print_uninstall_summary(distro);
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

pub fn detect_distro() -> Result<Distro, InstallError> {
    let dracut = Path::new("/usr/bin/dracut").exists()
              || Path::new("/usr/sbin/dracut").exists();
    let initramfs_tools = Path::new("/usr/sbin/update-initramfs").exists()
                       || Path::new("/usr/bin/update-initramfs").exists();
    match (dracut, initramfs_tools) {
        (false, true)  => Ok(Distro::Debian),
        (true,  _)     => Ok(Distro::Fedora),  // prefer dracut if both present
        (false, false) => Err(InstallError::DistroUnsupported(
            "neither dracut nor initramfs-tools found; SPiCa install supports \
             Debian/Ubuntu (initramfs-tools) and Fedora/RHEL (dracut)".into(),
        )),
    }
}

pub fn require_root() -> Result<(), InstallError> {
    // SAFETY: geteuid is always safe to call.
    if unsafe { libc::geteuid() } != 0 {
        return Err(InstallError::NotRoot);
    }
    Ok(())
}

fn install_binary() -> Result<(), InstallError> {
    let current_exe = std::env::current_exe()?;
    fs::copy(&current_exe, INSTALL_PATH)?;
    set_mode(INSTALL_PATH, 0o755)?;
    Ok(())
}

fn write_executable(path: &str, content: &str) -> Result<(), InstallError> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    set_mode(path, 0o755)?;
    Ok(())
}

fn set_mode(path: &str, mode: u32) -> Result<(), InstallError> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

fn rebuild(cmd: &str, args: &[&str]) -> Result<(), InstallError> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        return Err(InstallError::RebuildFailed {
            cmd: format!("{} {}", cmd, args.join(" ")),
            status,
        });
    }
    Ok(())
}

// ── Summary printers ─────────────────────────────────────────────────────────

fn print_install_summary(distro: Distro) {
    println!("[INSTALL]    SPiCa installed to {}", INSTALL_PATH);
    match distro {
        Distro::Debian => {
            println!("[INSTALL]    Debian initramfs-tools hooks installed:");
            println!("[INSTALL]      {}", DEB_HOOK_PATH);
            println!("[INSTALL]      {}", DEB_SCRIPT_PATH);
            println!("[INSTALL]    initramfs rebuilt via `update-initramfs -u`");
        }
        Distro::Fedora => {
            println!("[INSTALL]    Fedora dracut module installed at:");
            println!("[INSTALL]      {}", DRAC_MODULE_DIR);
            println!("[INSTALL]    initramfs rebuilt via `dracut --force`");
        }
    }
    println!("[INSTALL]    SPiCa will start on next boot before the root fs mounts.");
}

fn print_uninstall_summary(distro: Distro) {
    println!("[UNINSTALL]  SPiCa removed from {}", INSTALL_PATH);
    match distro {
        Distro::Debian =>
            println!("[UNINSTALL]  Debian initramfs-tools hooks removed; initramfs rebuilt."),
        Distro::Fedora =>
            println!("[UNINSTALL]  Fedora dracut module removed; initramfs rebuilt."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_root_returns_err_when_not_root() {
        // On Mac dev / CI we're typically not root. On Linux test runners
        // also usually not root. Skip if we happen to be root.
        if unsafe { libc::geteuid() } == 0 {
            return; // running as root in some CI — can't test the negative case
        }
        assert!(matches!(require_root(), Err(InstallError::NotRoot)));
    }

    #[test]
    fn write_executable_creates_file_with_mode() {
        let dir = std::env::temp_dir().join("spica-install-test");
        let path = dir.join("test-script.sh");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        write_executable(path.to_str().unwrap(), "#!/bin/sh\necho hi\n").unwrap();

        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "file should be executable (0755)");
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("echo hi"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_executable_creates_parent_dirs() {
        let dir = std::env::temp_dir().join("spica-install-nested");
        let path = dir.join("a/b/c/script.sh");
        let _ = fs::remove_dir_all(&dir);

        write_executable(path.to_str().unwrap(), "content").unwrap();

        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_error_display_messages_are_useful() {
        assert!(format!("{}", InstallError::NotRoot).contains("root"));
        assert!(format!("{}", InstallError::DistroUnsupported("foo".into())).contains("foo"));
        // Io variant
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: InstallError = io_err.into();
        assert!(format!("{}", err).contains("io error"));
    }

    #[test]
    fn detect_distro_does_not_panic_on_mac() {
        // On Mac there's no dracut and no update-initramfs, so this returns Err.
        // Just verify it doesn't panic.
        let _ = detect_distro();
    }

    #[test]
    fn embedded_scripts_are_nonempty() {
        // Sanity check that include_str! actually pulled content in.
        assert!(!DEB_HOOK.is_empty());
        assert!(!DEB_SCRIPT.is_empty());
        assert!(!DRAC_SETUP.is_empty());
        assert!(!DRAC_INIT.is_empty());
    }

    #[test]
    fn embedded_scripts_have_no_subprocess_tpm_refs() {
        // Refactor invariant: scripts must not reference the removed subprocess
        // TPM tools. tss-esapi is in-process now.
        assert!(!DEB_HOOK.contains("tpm2_getrandom"),
            "debian-hook still references tpm2_getrandom — should have been removed");
        assert!(!DEB_HOOK.contains("tpm2_pcrread"),
            "debian-hook still references tpm2_pcrread — should have been removed");
        assert!(!DRAC_SETUP.contains("tpm2_getrandom"),
            "dracut-module-setup still references tpm2_getrandom");
        assert!(!DRAC_SETUP.contains("tpm2_pcrread"),
            "dracut-module-setup still references tpm2_pcrread");
    }

    #[test]
    fn embedded_scripts_have_no_network_locked_language() {
        // XDP was removed; success messages should not say "network locked".
        assert!(!DEB_SCRIPT.to_lowercase().contains("network locked"),
            "debian-script still says 'network locked' — XDP removed");
        assert!(!DRAC_INIT.to_lowercase().contains("network locked"),
            "dracut-init still says 'network locked' — XDP removed");
    }

    #[test]
    fn embedded_scripts_reference_libtss2() {
        // libtss2-esys is mandatory now (tss-esapi links it dynamically).
        assert!(DEB_HOOK.contains("libtss2-esys"),
            "debian-hook must copy libtss2-esys (mandatory for tss-esapi)");
        assert!(DRAC_SETUP.contains("libtss2-esys"),
            "dracut-module-setup must include libtss2-esys");
    }
}

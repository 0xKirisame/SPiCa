//! `/proc` enumeration helper.
//!
//! Returns the set of numeric TGIDs currently visible in `/proc`. Used by
//! `main.rs` to seed the ProcessRegistry at startup and by `detect::evaluate`
//! on every tick to drive the DKOM / GHOST / SILENT predicates.
//!
//! Intentionally NOT trait-abstracted — `detect::evaluate` already accepts
//! `&HashSet<u32>` as input, so tests construct synthetic sets directly. A
//! trait here would add indirection without enabling any test that isn't
//! already possible. See spec §11.

use std::collections::HashSet;
use std::ffi::CString;
use std::fs;

/// Read the numeric subdirectories of `/proc` and return them as a set of TGIDs.
///
/// Uses Rust's `std::fs::read_dir` which calls `getdents64` via raw syscall,
/// bypassing libc's `readdir`. This means LD_PRELOAD rootkits (Symbiote,
/// JynxKit, Azazel, Medusa) that hook libc's `readdir` CANNOT hide processes
/// from this function.
pub fn read_tgids() -> HashSet<u32> {
    let mut set = HashSet::new();
    let Ok(entries) = fs::read_dir("/proc") else { return set };
    for entry in entries.flatten() {
        if let Ok(n) = entry.file_name().to_string_lossy().parse::<u32>() {
            set.insert(n);
        }
    }
    set
}

/// Read `/proc` TGIDs via libc's `readdir` — the function hooked by
/// LD_PRELOAD rootkits. When compared against `read_tgids()` (which
/// uses the raw `getdents64` syscall), any discrepancy reveals
/// processes hidden by userspace library interception.
///
/// Symbiote hooks `readdir`/`readdir64` to hide itself and its
/// child processes. This function goes THROUGH that hook, so hidden
/// processes are absent from the returned set. The comparison in
/// `evaluate()` detects the difference.
pub fn read_tgids_libc() -> HashSet<u32> {
    let mut set = HashSet::new();
    let path = match CString::new("/proc") {
        Ok(p) => p,
        Err(_) => return set,
    };
    unsafe {
        let dir = libc::opendir(path.as_ptr());
        if dir.is_null() {
            return set;
        }
        loop {
            let entry = libc::readdir(dir);
            if entry.is_null() {
                break;
            }
            let name_ptr = (*entry).d_name.as_ptr();
            let name = std::ffi::CStr::from_ptr(name_ptr);
            if let Ok(s) = name.to_str() {
                if let Ok(n) = s.parse::<u32>() {
                    set.insert(n);
                }
            }
        }
        libc::closedir(dir);
    }
    set
}

/// Resolve a kernel PID (thread ID) to its TGID (thread group ID) via
/// `/proc/<pid>/status`. Returns `None` if the thread has exited or the
/// entry is unreadable.
pub fn resolve_tgid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

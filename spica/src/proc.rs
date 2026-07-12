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
use std::fs;

/// Read the numeric subdirectories of `/proc` and return them as a set of TGIDs.
///
/// Any non-numeric entry is silently skipped (`.`, `..`, `self`, `mounts`,
/// `cpuinfo`, etc.). Errors are silently treated as empty set — the caller
/// handles empty-set semantics correctly (registry gets seeded with nothing,
/// DKOM predicates trip for any eBPF-observed process).
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

/// Resolve a kernel PID (thread ID) to its TGID (thread group ID) via
/// `/proc/<pid>/status`. Returns `None` if the thread has exited or the
/// entry is unreadable.
///
/// The sched_switch tracepoint reports `next_pid` which is the kernel's
/// internal PID (thread ID / LWP). For multi-threaded processes, this
/// differs from the TGID that `/proc` lists. Without this resolution,
/// threads would appear as DKOM (scheduled but absent from `/proc`).
pub fn resolve_tgid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

//! SPiCa detection FSM — pure logic, no I/O.
//!
//! All functions here are deterministic over their inputs (ProcessRegistry,
//! /proc tgids, current time). No file reads, no printing, no eBPF. This
//! module is the testable surface of SPiCa's detection logic — every other
//! module feeds it data and consumes its output.
//!
//! See docs/superpowers/specs/2026-06-20-spica-v4-refactor-design.md §5-6
//! for the type-system and FSM design rationale.

use std::collections::{HashMap, HashSet};

use spica_common::ProcessInfo;

// ── Detection classes ────────────────────────────────────────────────────────

/// All detection classes — the public emission type. Used in `Detection.class`
/// for both tick-driven and event-driven alerts. Consumers (main.rs) format
/// and print these.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectionClass {
    Dkm,        // scheduled by kernel, absent from /proc
    Ghost,      // in /proc, never observed by eBPF
    Tamper,     // NMI alive, sched silent (tracepoint suppression) OR canary mismatch
    Silent,     // both channels dead (total observation loss)
    Dupe,       // same TGID, different start_time_ns
    LkmAllow,   // boot-window module load
    LkmDeny,    // post-gate module load attempt
    Watchdog,   // prior instance killed ungracefully
}

impl DetectionClass {
    /// Uppercased label for the alert line, e.g. `DKOM`, `LKM-DENY`.
    pub fn label(self) -> &'static str {
        match self {
            DetectionClass::Dkm      => "DKOM",
            DetectionClass::Ghost    => "GHOST",
            DetectionClass::Tamper   => "TAMPER",
            DetectionClass::Silent   => "SILENT",
            DetectionClass::Dupe     => "DUPE",
            DetectionClass::LkmAllow => "LKM-ALLOW",
            DetectionClass::LkmDeny  => "LKM-DENY",
            DetectionClass::Watchdog => "WATCHDOG",
        }
    }
}

/// Internal storage index for per-tick classes that need suspect-since +
/// cooldown state. Distinct from DetectionClass because event-driven classes
/// (Dupe, LkmAllow, LkmDeny, Watchdog) fire once on arrival and don't need
/// per-record suspect/cooldown tracking.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessClass {
    Dkom = 0,
    Ghost = 1,
    Tamper = 2,
    Silent = 3,
}

impl ProcessClass {
    pub const COUNT: usize = 4;

    /// Map to the corresponding public DetectionClass variant.
    pub fn to_detection_class(self) -> DetectionClass {
        match self {
            ProcessClass::Dkom   => DetectionClass::Dkm,
            ProcessClass::Ghost  => DetectionClass::Ghost,
            ProcessClass::Tamper => DetectionClass::Tamper,
            ProcessClass::Silent => DetectionClass::Silent,
        }
    }

    /// All variants in array-index order. Used by evaluate() to iterate.
    pub const ALL: [ProcessClass; ProcessClass::COUNT] = [
        ProcessClass::Dkom,
        ProcessClass::Ghost,
        ProcessClass::Tamper,
        ProcessClass::Silent,
    ];
}

// ── Per-record state ─────────────────────────────────────────────────────────

/// Per-class suspect + cooldown tracking. Indexed inside ProcessRecord by
/// ProcessClass discriminant.
///
/// `0` for either field means "not set":
///   - `suspect_since == 0`: not currently in suspect state
///   - `last_emitted == 0`:  never emitted (so first eligible fire always passes cooldown)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ClassState {
    pub suspect_since: u64,   // nanos since process epoch; 0 = not suspect
    pub last_emitted:   u64,   // nanos since process epoch; 0 = never emitted
}

/// One record per tracked TGID. Sized to fit in two cache lines (96 bytes).
///
/// Time fields are `u64` nanoseconds from a process-local epoch captured at
/// SPiCa startup. Cheaper and niche-friendlier than `std::time::Instant`.
/// `0` means "never" for the `*_last` and ClassState fields; `first_seen` is
/// always set on creation and never 0.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProcessRecord {
    pub start_time_ns: u64,                          // 8  (kernel task birth time)
    pub first_seen:    u64,                          // 8  (nanos since process epoch)
    pub sched_last:    u64,                          // 8  (nanos since epoch; 0 = never)
    pub nmi_last:      u64,                          // 8  (nanos since epoch; 0 = never)
    pub classes:       [ClassState; ProcessClass::COUNT],  // 64 (4 × 16)
}

// Lock the layout — catches accidental padding regressions during refactor.
// Assertion lives at the type level so it's checked at every compile.
const _: () = assert!(std::mem::size_of::<ClassState>() == 16);
const _: () = assert!(std::mem::size_of::<ProcessRecord>() == 96);

impl ProcessRecord {
    /// Used when a new TGID is first observed via sched/NMI event.
    pub fn new(start_time_ns: u64, now_nanos: u64) -> Self {
        Self {
            start_time_ns,
            first_seen: now_nanos,
            sched_last: 0,
            nmi_last: 0,
            classes: [ClassState { suspect_since: 0, last_emitted: 0 }; ProcessClass::COUNT],
        }
    }

    /// Used when seeding the registry from /proc at startup. `sched_last` is
    /// set to `now_nanos` so the seeded process doesn't immediately trigger
    /// GHOST (we treat it as "already observed on the sched channel" since
    /// /proc visibility is itself a form of observation).
    pub fn seeded(now_nanos: u64) -> Self {
        Self {
            start_time_ns: 0,
            first_seen: now_nanos,
            sched_last: now_nanos,
            nmi_last: 0,
            classes: [ClassState { suspect_since: 0, last_emitted: 0 }; ProcessClass::COUNT],
        }
    }
}

/// The registry of all currently-tracked processes, keyed by TGID.
pub type ProcessRegistry = HashMap<u32, ProcessRecord>;

/// One emitted detection. Returned by evaluate() and the on_*_event handlers.
/// The caller owns formatting and side effects.
#[derive(Debug, Clone)]
pub struct Detection {
    pub class: DetectionClass,
    pub tgid: u32,
    /// How long the suspicious condition has held (nanos). 0 for event-driven
    /// classes (Dupe, LkmAllow, LkmDeny) that fire instantly.
    pub elapsed: u64,
    /// Human-readable context shown after the alert tag.
    pub details: String,
}

// ── Time / threshold constants ───────────────────────────────────────────────
//
// Preserved exactly from v3.1 behavior. Adjust via this block only.

pub const TICK_RATE_MS:             u64 = 100;
pub const SUSPECT_THRESHOLD_NANOS:  u64 =     2_000_000_000;  // 2 sec
pub const GHOST_THRESHOLD_NANOS:    u64 =     5_000_000_000;  // 5 sec
pub const ALERT_COOLDOWN_NANOS:     u64 =    30_000_000_000;  // 30 sec
pub const GRACE_WINDOW_NANOS:       u64 =        50_000_000;  // 50 ms
pub const STALE_NANOS:              u64 =    10_000_000_000;  // 10 sec
pub const SCHED_LIVENESS_NANOS:     u64 =       500_000_000;  // 500 ms
pub const NMI_LIVENESS_NANOS:       u64 =     1_000_000_000;  // 1 sec

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_record_is_96_bytes() {
        // Belt-and-suspenders over the const assert. Surface-level so test
        // runners report it cleanly instead of as a compile error.
        assert_eq!(std::mem::size_of::<ProcessRecord>(), 96);
    }

    #[test]
    fn class_state_is_16_bytes() {
        assert_eq!(std::mem::size_of::<ClassState>(), 16);
    }

    #[test]
    fn process_class_count_matches_all_len() {
        assert_eq!(ProcessClass::ALL.len(), ProcessClass::COUNT);
    }

    #[test]
    fn process_class_to_detection_class_covers_first_four() {
        assert_eq!(ProcessClass::Dkom.to_detection_class(),   DetectionClass::Dkm);
        assert_eq!(ProcessClass::Ghost.to_detection_class(),  DetectionClass::Ghost);
        assert_eq!(ProcessClass::Tamper.to_detection_class(), DetectionClass::Tamper);
        assert_eq!(ProcessClass::Silent.to_detection_class(), DetectionClass::Silent);
    }

    #[test]
    fn detection_class_labels_are_uppercase_no_spaces() {
        // Sanity check on the formatting that main.rs will rely on.
        assert_eq!(DetectionClass::Dkm.label(), "DKOM");
        assert_eq!(DetectionClass::LkmDeny.label(), "LKM-DENY");
        assert_eq!(DetectionClass::Watchdog.label(), "WATCHDOG");
    }

    #[test]
    fn process_record_new_zeroes_last_seen_fields() {
        let rec = ProcessRecord::new(123, 1000);
        assert_eq!(rec.start_time_ns, 123);
        assert_eq!(rec.first_seen, 1000);
        assert_eq!(rec.sched_last, 0);
        assert_eq!(rec.nmi_last, 0);
        for c in ProcessClass::ALL {
            assert_eq!(rec.classes[c as usize].suspect_since, 0);
            assert_eq!(rec.classes[c as usize].last_emitted, 0);
        }
    }

    #[test]
    fn process_record_seeded_pretends_sched_was_seen() {
        // Seeded records have sched_last set so they don't trip GHOST.
        let rec = ProcessRecord::seeded(5000);
        assert_eq!(rec.first_seen, 5000);
        assert_eq!(rec.sched_last, 5000);
        assert_eq!(rec.nmi_last, 0);
    }

    // Silence unused-import warning when ProcessInfo is only referenced by
    // later task additions (evaluate(), on_*_event).
    #[test]
    fn _process_info_type_is_in_scope() {
        let _ = ProcessInfo {
            pid: 0, tgid: 0, comm: [0u8; 16],
            last_seen: 0, start_time_ns: 0, cpu: 0, event_type: 0,
        };
    }
}

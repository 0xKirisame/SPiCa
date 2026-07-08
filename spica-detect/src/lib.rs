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
    ///
    /// `now_nanos` is bumped to a minimum of 1 internally because 0 is the
    /// "never seen" sentinel and would collide. The first tick after startup
    /// will see `sched age = now - 1` which is essentially `now` — correct.
    pub fn seeded(now_nanos: u64) -> Self {
        let now = if now_nanos == 0 { 1 } else { now_nanos };
        Self {
            start_time_ns: 0,
            first_seen: now,
            sched_last: now,
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

// ── FSM implementation ───────────────────────────────────────────────────────

/// Pure tick-driven evaluation. No I/O, no printing. Reads the registry +
/// current /proc snapshot, mutates per-record suspect/cooldown state, pushes
/// firing `Detection`s into the caller-owned `out` buffer.
///
/// `out` is cleared at the start. Caller reuses the same `Vec` across ticks
/// to avoid per-tick allocation (see `evaluate_does_not_allocate_when_nothing_changes`).
pub fn evaluate(
    registry: &mut ProcessRegistry,
    proc_tgids: &HashSet<u32>,
    now: u64,
    out: &mut Vec<Detection>,
) {
    out.clear();

    // 1. Seed records for any /proc tgid we don't know yet. This is the
    //    precondition for GHOST detection: a /proc entry that's never been
    //    observed by an eBPF channel.
    for &tgid in proc_tgids {
        registry.entry(tgid).or_insert_with(|| ProcessRecord::seeded(now));
    }

    // 2. Per-record evaluation.
    for (&tgid, record) in registry.iter_mut() {
        // Grace window: skip freshly-forked / freshly-seeded records so they
        // don't fire before the channels have had a chance to observe them.
        if now.wrapping_sub(record.first_seen) < GRACE_WINDOW_NANOS {
            continue;
        }

        let in_proc    = proc_tgids.contains(&tgid);
        let sched_live = record.sched_last != 0 && now.wrapping_sub(record.sched_last) < SCHED_LIVENESS_NANOS;
        let nmi_live   = record.nmi_last   != 0 && now.wrapping_sub(record.nmi_last)   < NMI_LIVENESS_NANOS;

        // Per-class predicate + threshold. The loop body handles suspect-since
        // tracking, threshold check, and cooldown uniformly.
        for class in ProcessClass::ALL {
            let (predicate, threshold, details) = match class {
                ProcessClass::Dkom => (
                    !in_proc && (sched_live || nmi_live),
                    SUSPECT_THRESHOLD_NANOS,
                    format!("hidden {:.1}s", now.saturating_sub(
                        record.classes[class as usize].suspect_since) as f64 / 1e9),
                ),
                ProcessClass::Tamper => (
                    in_proc && nmi_live && !sched_live && record.sched_last != 0,
                    SUSPECT_THRESHOLD_NANOS,
                    "NMI alive, tracepoint SILENT".to_string(),
                ),
                ProcessClass::Silent => (
                    // Only trigger for processes that sched_switch IS seeing (actively being scheduled)
                    // but NMI never sees (despite them being "active enough" to run)
                    // This eliminates false positives from sleeping/idle processes
                    in_proc && sched_live && !nmi_live && record.sched_last != 0,
                    GHOST_THRESHOLD_NANOS,
                    "scheduled but NMI-invisible".to_string(),
                ),
                ProcessClass::Ghost => (
                    in_proc && record.sched_last == 0 && record.nmi_last == 0,
                    GHOST_THRESHOLD_NANOS,
                    "present in /proc, never seen by eBPF".to_string(),
                ),
            };

            let cs = &mut record.classes[class as usize];
            if predicate {
                if cs.suspect_since == 0 {
                    cs.suspect_since = now;
                }
                if now.saturating_sub(cs.suspect_since) > threshold {
                    let should_emit = cs.last_emitted == 0
                        || now.saturating_sub(cs.last_emitted) > ALERT_COOLDOWN_NANOS;
                    if should_emit {
                        cs.last_emitted = now;
                        out.push(Detection {
                            class: class.to_detection_class(),
                            tgid,
                            elapsed: now.saturating_sub(cs.suspect_since),
                            details,
                        });
                    }
                }
            } else {
                cs.suspect_since = 0;
                cs.last_emitted = 0;
            }
        }
    }

    // 3. Eviction: drop records that are stale on both channels AND not in /proc.
    //    Keeps registry bounded. Records in /proc are always retained (they're
    //    either active processes or GHOST suspects we want to keep tracking).
    registry.retain(|&tgid, record| {
        let sched_age = if record.sched_last == 0 { u64::MAX } else { now.saturating_sub(record.sched_last) };
        let nmi_age   = if record.nmi_last   == 0 { u64::MAX } else { now.saturating_sub(record.nmi_last)   };
        sched_age < STALE_NANOS || nmi_age < STALE_NANOS || proc_tgids.contains(&tgid)
    });
}

// ── Event handlers ───────────────────────────────────────────────────────────
//
// Pure functions. Caller passes the decoded event + current time + registry;
// handler returns Option<Detection> (Some for event-driven classes like DUPE).

/// Called when a sched_switch event arrives. Updates `sched_last` on the
/// record and checks for DUPE (start_time_ns mismatch — same TGID, different
/// kernel birth timestamp). Returns Some(DUPE) if detected, else None.
pub fn on_sched_event(
    info: ProcessInfo,
    registry: &mut ProcessRegistry,
    now: u64,
) -> Option<Detection> {
    if info.tgid == 0 {
        return None;
    }
    let record = registry.entry(info.tgid)
        .or_insert_with(|| ProcessRecord::new(info.start_time_ns, now));

    // DUPE detection — same TGID, different start_time_ns.
    // Only meaningful when both values are non-zero (0 = unknown).
    if record.start_time_ns != 0
        && info.start_time_ns != 0
        && record.start_time_ns != info.start_time_ns
    {
        record.sched_last = info.last_seen;
        return Some(Detection {
            class: DetectionClass::Dupe,
            tgid: info.tgid,
            elapsed: 0,
            details: "task_struct spoofing suspected".to_string(),
        });
    }

    // Anchor start_time_ns if we didn't have one yet.
    if record.start_time_ns == 0 && info.start_time_ns != 0 {
        record.start_time_ns = info.start_time_ns;
    }

    record.sched_last = info.last_seen;
    None
}

/// Called when a normal NMI heartbeat event arrives (event_type == 0).
/// Updates `nmi_last` on the record. Always returns None — NMI doesn't
/// drive any event-driven detection class directly.
///
/// TAMPER via canary mismatch (event_type == 1) is handled by the caller
/// (main.rs) directly — it's a raw sentinel, not FSM-driven.
pub fn on_nmi_event(info: ProcessInfo, registry: &mut ProcessRegistry, _now: u64) {
    if info.tgid == 0 {
        return;
    }
    let record = registry.entry(info.tgid)
        .or_insert_with(|| ProcessRecord::new(0, info.last_seen));
    record.nmi_last = info.last_seen;
}

/// Called when an LKM load attempt event arrives. Always returns a Detection
/// (either LkmAllow during boot window or LkmDeny after gate locked). There's
/// no "no-op" outcome — every READING_MODULE intercept emits something.
///
/// The comm field from the event is folded into the details string so the
/// caller doesn't need to /proc/<tgid>/comm lookup (the calling process may
/// have already exited — insmod returns fast).
pub fn on_lkm_event(ev: spica_common::LkmEvent) -> Detection {
    let class = if ev.allowed == 1 { DetectionClass::LkmAllow } else { DetectionClass::LkmDeny };
    let comm = comm_str(&ev.comm);
    let detail = if ev.allowed == 1 {
        format!("module loaded (boot window, gate open) [{}]", comm)
    } else {
        format!("module load blocked (gate locked) [{}]", comm)
    };
    Detection {
        class,
        tgid: ev.tgid,
        elapsed: 0,
        details: detail,
    }
}

/// Format the kernel `comm` field (16-byte null-padded) as a UTF-8 string.
fn comm_str(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Type-level sanity tests (kept from Task 6) ───────────────────────────

    #[test]
    fn process_record_is_96_bytes() {
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
        let rec = ProcessRecord::seeded(5000);
        assert_eq!(rec.first_seen, 5000);
        assert_eq!(rec.sched_last, 5000);
        assert_eq!(rec.nmi_last, 0);
    }

    // ── evaluate() FSM tests ─────────────────────────────────────────────────

    // Tests that expect a fire pre-populate `suspect_since` to simulate that
    // the predicate has been continuously true for >threshold. The FSM refuses
    // to fire on the first tick the predicate becomes true — it waits for the
    // threshold to elapse. This is correct behavior (avoids flapping on
    // transient blips); tests just have to model history.

    #[test]
    fn dkom_fires_when_scheduled_but_absent_from_proc() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let now = 5_000_000_000;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = now - 100_000_000;  // alive
        rec.classes[ProcessClass::Dkom as usize].suspect_since =
            now - SUSPECT_THRESHOLD_NANOS - 1;
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new();
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, now, &mut out);
        assert!(out.iter().any(|d| d.class == DetectionClass::Dkm),
            "expected DKOM, got: {:?}", out);
    }

    #[test]
    fn dkom_respects_grace_window() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let now = 100u64;  // very recent first_seen
        let mut rec = ProcessRecord::new(0, now);
        rec.sched_last = now;
        // Even with ancient suspect_since, grace should suppress.
        rec.classes[ProcessClass::Dkom as usize].suspect_since = 1;
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new();
        let mut out = Vec::new();

        let tick = now + GRACE_WINDOW_NANOS - 1;
        evaluate(&mut reg, &proc_tgids, tick, &mut out);
        assert!(out.is_empty(), "no alerts during grace window");
    }

    #[test]
    fn dkom_respects_cooldown() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let t1 = 5_000_000_000u64;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = t1;
        rec.classes[ProcessClass::Dkom as usize].suspect_since =
            t1 - SUSPECT_THRESHOLD_NANOS - 1;
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new();
        let mut out = Vec::new();

        // Tick 1: fires (suspect_since pre-set past threshold)
        evaluate(&mut reg, &proc_tgids, t1, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].class, DetectionClass::Dkm);
        out.clear();

        // Tick 2 within cooldown — no re-fire. Keep sched alive.
        let t2 = t1 + 1_000_000;
        reg.get_mut(&tgid).unwrap().sched_last = t2;
        evaluate(&mut reg, &proc_tgids, t2, &mut out);
        assert!(out.is_empty(), "no re-fire within cooldown");
        out.clear();

        // Tick 3 past cooldown — re-fires
        let t3 = t1 + ALERT_COOLDOWN_NANOS + 1;
        reg.get_mut(&tgid).unwrap().sched_last = t3;
        evaluate(&mut reg, &proc_tgids, t3, &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn dkom_clears_when_process_reappears_in_proc() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);  // first_seen=0
        rec.sched_last = 1;
        rec.classes[ProcessClass::Dkom as usize].suspect_since = 100;
        rec.classes[ProcessClass::Dkom as usize].last_emitted = 200;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut out = Vec::new();

        // Tick past grace (first_seen=0, now must be > GRACE_WINDOW)
        let now = 100_000_000;
        evaluate(&mut reg, &proc_tgids, now, &mut out);

        // DKOM predicate false (now in /proc) → suspect state cleared, no fire
        assert!(out.is_empty());
        let cs = &reg.get(&tgid).unwrap().classes[ProcessClass::Dkom as usize];
        assert_eq!(cs.suspect_since, 0);
        assert_eq!(cs.last_emitted, 0);
    }

    #[test]
    fn ghost_fires_when_in_proc_never_observed() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let now = 10_000_000_000;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 0;  // never seen
        rec.nmi_last = 0;
        rec.classes[ProcessClass::Ghost as usize].suspect_since =
            now - GHOST_THRESHOLD_NANOS - 1;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, now, &mut out);
        assert!(out.iter().any(|d| d.class == DetectionClass::Ghost),
            "expected GHOST, got: {:?}", out);
    }

    #[test]
    fn tamper_fires_when_nmi_alive_but_sched_silent() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let now = 5_000_000_000;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1;  // was seen, but old → dead
        rec.nmi_last = now - 100_000_000;  // alive (100ms < 1s)
        rec.classes[ProcessClass::Tamper as usize].suspect_since =
            now - SUSPECT_THRESHOLD_NANOS - 1;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, now, &mut out);
        assert!(out.iter().any(|d| d.class == DetectionClass::Tamper),
            "expected TAMPER, got: {:?}", out);
    }

    #[test]
    fn silent_fires_when_both_channels_dead() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let now = 10_000_000_000;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1;  // was seen, old
        rec.nmi_last = 1;    // was seen, old
        rec.classes[ProcessClass::Silent as usize].suspect_since =
            now - GHOST_THRESHOLD_NANOS - 1;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, now, &mut out);
        assert!(out.iter().any(|d| d.class == DetectionClass::Silent),
            "expected SILENT, got: {:?}", out);
    }

    #[test]
    fn evaluate_evicts_records_stale_on_both_channels_and_not_in_proc() {
        let mut reg = ProcessRegistry::new();
        let tgid = 9999u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1;
        rec.nmi_last = 1;
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new();  // not in /proc either
        let mut out = Vec::new();

        // Tick past STALE_NANOS → record should be evicted
        evaluate(&mut reg, &proc_tgids, STALE_NANOS + 1, &mut out);
        assert!(!reg.contains_key(&tgid), "stale record should be evicted");
    }

    #[test]
    fn evaluate_retains_records_that_are_in_proc_even_if_stale() {
        let mut reg = ProcessRegistry::new();
        let tgid = 9999u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1;
        rec.nmi_last = 1;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, STALE_NANOS + 1, &mut out);
        assert!(reg.contains_key(&tgid), "in-proc record should be retained");
    }

    #[test]
    fn evaluate_does_not_reallocate_out_when_empty() {
        let mut reg = ProcessRegistry::new();
        let proc_tgids = HashSet::new();
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, 0, &mut out);
        assert_eq!(out.len(), 0);
        assert!(out.capacity() == 0, "no allocation when nothing fires");

        // Re-run — capacity should remain 0
        evaluate(&mut reg, &proc_tgids, 1_000_000_000, &mut out);
        assert_eq!(out.capacity(), 0, "no growth on empty re-run");
    }

    // ── on_sched_event / DUPE tests ──────────────────────────────────────────

    fn proc_info(tgid: u32, start_time: u64, last_seen: u64) -> ProcessInfo {
        ProcessInfo {
            pid: tgid, tgid, comm: [0u8; 16],
            last_seen, start_time_ns: start_time, cpu: 0, event_type: 0,
        }
    }

    #[test]
    fn on_sched_event_creates_record_for_new_tgid() {
        let mut reg = ProcessRegistry::new();
        let info = proc_info(1234, 999, 5000);
        let result = on_sched_event(info, &mut reg, 5000);

        assert!(result.is_none(), "first sighting should not fire DUPE");
        let rec = reg.get(&1234).unwrap();
        assert_eq!(rec.start_time_ns, 999);
        assert_eq!(rec.sched_last, 5000);
    }

    #[test]
    fn on_sched_event_fires_dupe_on_start_time_mismatch() {
        let mut reg = ProcessRegistry::new();
        // Existing record anchored at start_time=999
        reg.insert(1234, ProcessRecord::new(999, 0));

        // New event claims same TGID but different start_time
        let info = proc_info(1234, 8888, 5000);
        let result = on_sched_event(info, &mut reg, 5000);

        assert!(result.is_some());
        let d = result.unwrap();
        assert_eq!(d.class, DetectionClass::Dupe);
        assert_eq!(d.tgid, 1234);
    }

    #[test]
    fn on_sched_event_anchors_start_time_if_unknown() {
        let mut reg = ProcessRegistry::new();
        // Existing record with start_time=0 (was seeded from /proc)
        reg.insert(1234, ProcessRecord::new(0, 0));

        // First real observation provides the start_time
        let info = proc_info(1234, 7777, 5000);
        on_sched_event(info, &mut reg, 5000);

        let rec = reg.get(&1234).unwrap();
        assert_eq!(rec.start_time_ns, 7777, "should be anchored from event");
    }

    #[test]
    fn on_sched_event_ignores_zero_tgid() {
        let mut reg = ProcessRegistry::new();
        let info = proc_info(0, 999, 5000);
        let result = on_sched_event(info, &mut reg, 5000);

        assert!(result.is_none());
        assert!(reg.is_empty(), "zero-TGID event should not create a record");
    }

    // ── on_nmi_event tests ───────────────────────────────────────────────────

    #[test]
    fn on_nmi_event_updates_nmi_last() {
        let mut reg = ProcessRegistry::new();
        let info = proc_info(1234, 0, 7777);
        on_nmi_event(info, &mut reg, 7777);

        let rec = reg.get(&1234).unwrap();
        assert_eq!(rec.nmi_last, 7777);
    }

    #[test]
    fn on_nmi_event_ignores_zero_tgid() {
        let mut reg = ProcessRegistry::new();
        let info = proc_info(0, 0, 7777);
        on_nmi_event(info, &mut reg, 7777);
        assert!(reg.is_empty());
    }

    // ── on_lkm_event tests ───────────────────────────────────────────────────

    fn lkm_event(tgid: u32, allowed: bool) -> spica_common::LkmEvent {
        spica_common::LkmEvent {
            pid: tgid, tgid, comm: [0u8; 16],
            ktime_ns: 0, allowed: if allowed { 1 } else { 0 }, _pad: 0,
        }
    }

    #[test]
    fn on_lkm_event_returns_allow_when_gate_open() {
        let d = on_lkm_event(lkm_event(1234, true));
        assert_eq!(d.class, DetectionClass::LkmAllow);
        assert_eq!(d.tgid, 1234);
    }

    #[test]
    fn on_lkm_event_returns_deny_when_gate_closed() {
        let d = on_lkm_event(lkm_event(1234, false));
        assert_eq!(d.class, DetectionClass::LkmDeny);
    }
}


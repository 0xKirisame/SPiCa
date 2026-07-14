//! SPiCa detection FSM — pure logic, no I/O.
//!
//! All functions here are deterministic over their inputs (ProcessRegistry,
//! /proc tgids, current time). No file reads, no printing, no eBPF. This
//! module is the testable surface of SPiCa's detection logic — every other
//! module feeds it data and consumes its output.

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
    Ghost,      // in /proc, never observed by sched_switch
    Tamper,     // NMI detected sched_switch heartbeat frozen
    Silent,     // channel-level observation loss (sched or NMI dead)
    Dupe,       // same TGID, different start_time_ns
    LkmAllow,   // boot-window module load
    LkmDeny,    // post-gate module load attempt
    Watchdog,   // prior instance killed ungracefully
    Hook,       // LD_PRELOAD rootkit hiding processes from libc readdir
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
            DetectionClass::Hook     => "HOOK",
        }
    }
}

/// Internal storage index for per-tick classes that need suspect-since +
/// cooldown state. Distinct from DetectionClass because event-driven classes
/// (Dupe, LkmAllow, LkmDeny, Watchdog, Tamper, Silent) fire once on arrival
/// or are channel-level, and don't need per-record suspect/cooldown tracking.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessClass {
    Dkom = 0,
    Ghost = 1,
}

impl ProcessClass {
    pub const COUNT: usize = 2;

    /// Map to the corresponding public DetectionClass variant.
    pub fn to_detection_class(self) -> DetectionClass {
        match self {
            ProcessClass::Dkom  => DetectionClass::Dkm,
            ProcessClass::Ghost => DetectionClass::Ghost,
        }
    }

    /// All variants in array-index order. Used by evaluate() to iterate.
    pub const ALL: [ProcessClass; ProcessClass::COUNT] = [
        ProcessClass::Dkom,
        ProcessClass::Ghost,
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

/// One record per tracked TGID.
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
    pub classes:       [ClassState; ProcessClass::COUNT],  // 32 (2 x 16)
}

// Lock the layout — catches accidental padding regressions during refactor.
const _: () = assert!(std::mem::size_of::<ClassState>() == 16);
const _: () = assert!(std::mem::size_of::<ProcessRecord>() == 56);

impl ProcessRecord {
    /// Used when a new TGID is first observed via a sched event.
    pub fn new(start_time_ns: u64, now_nanos: u64) -> Self {
        Self {
            start_time_ns,
            first_seen: now_nanos,
            sched_last: 0,
            classes: [ClassState { suspect_since: 0, last_emitted: 0 }; ProcessClass::COUNT],
        }
    }

    /// Used when seeding the registry from /proc at startup. `sched_last` is
    /// set to `now_nanos` so the seeded process doesn't immediately trigger
    /// GHOST — we treat /proc visibility as a form of observation. Real sched
    /// events will update `sched_last` to a fresh timestamp; if a process is
    /// hidden from both sched AND /proc, DKOM handles it (sched_live && !in_proc).
    ///
    /// GHOST (in /proc but never seen by sched) is difficult to distinguish
    /// from legitimate idle processes without additional heuristics; the
    /// current predicate `sched_last == 0` is effectively disabled for seeded
    /// records. A smarter GHOST (e.g. tracking `sched_observed` as a separate
    /// flag with idle-process filtering) is a future enhancement.
    ///
    /// `now_nanos` is bumped to a minimum of 1 internally because 0 is the
    /// "never seen" sentinel and would collide.
    pub fn seeded(now_nanos: u64) -> Self {
        let now = if now_nanos == 0 { 1 } else { now_nanos };
        Self {
            start_time_ns: 0,
            first_seen: now,
            sched_last: now,
            classes: [ClassState { suspect_since: 0, last_emitted: 0 }; ProcessClass::COUNT],
        }
    }
}

/// The registry of all currently-tracked processes, keyed by TGID.
pub type ProcessRegistry = HashMap<u32, ProcessRecord>;

/// Channel-level cooldown state for SILENT alerts. Owned by the caller
/// (main.rs) and passed mutably to evaluate() across ticks.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ChannelCooldown {
    /// Last emit time for sched-channel SILENT (0 = never emitted / recovered).
    pub sched_silent_last: u64,
    /// Last emit time for NMI-channel SILENT (0 = never emitted / recovered).
    pub nmi_silent_last: u64,
    /// Last emit time for HOOK alerts (0 = never emitted / recovered).
    pub hook_last_emitted: u64,
}

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

pub const TICK_RATE_MS:             u64 = 100;
pub const SUSPECT_THRESHOLD_NANOS:  u64 =     2_000_000_000;  // 2 sec
pub const GHOST_THRESHOLD_NANOS:    u64 =     5_000_000_000;  // 5 sec
pub const ALERT_COOLDOWN_NANOS:     u64 =    30_000_000_000;  // 30 sec
pub const GRACE_WINDOW_NANOS:       u64 =        50_000_000;  // 50 ms
pub const STALE_NANOS:              u64 =    10_000_000_000;  // 10 sec
pub const SCHED_LIVENESS_NANOS:     u64 =       500_000_000;  // 500 ms
pub const CHANNEL_DEAD_NANOS:       u64 =     5_000_000_000;  // 5 sec — channel-level death

// ── FSM implementation ───────────────────────────────────────────────────────

/// Pure tick-driven evaluation. No I/O, no printing. Reads the registry +
/// current /proc snapshot + channel timestamps, mutates per-record and
/// channel-level suspect/cooldown state, pushes firing `Detection`s into the
/// caller-owned `out` buffer.
///
/// `last_nmi_hb` is the process-local nanos timestamp of the last NMI
/// heartbeat event received. 0 means NMI has never been heard from (early
/// startup — channel-level SILENT will not fire until CHANNEL_DEAD_NANOS
/// elapses, providing a natural grace period).
///
/// `channel_cd` tracks cooldown state for channel-level SILENT alerts.
/// The caller owns it and reuses it across ticks.
pub fn evaluate(
    registry: &mut ProcessRegistry,
    proc_tgids: &HashSet<u32>,
    proc_tgids_libc: &HashSet<u32>,
    now: u64,
    last_nmi_hb: u64,
    channel_cd: &mut ChannelCooldown,
    out: &mut Vec<Detection>,
) {
    out.clear();

    // 1. Seed records for any /proc tgid we don't know yet.
    for &tgid in proc_tgids {
        registry.entry(tgid).or_insert_with(|| ProcessRecord::seeded(now));
    }

    // 2. HOOK detection — LD_PRELOAD rootkit hiding processes from libc readdir.
    //
    // read_tgids() uses raw getdents64 (bypasses LD_PRELOAD).
    // read_tgids_libc() uses libc readdir (goes through LD_PRELOAD hooks).
    // If raw sees PIDs that libc doesn't, an LD_PRELOAD rootkit (Symbiote,
    // JynxKit, Azazel, Medusa) is hiding processes from userspace tools.
    let hidden_by_libc: Vec<u32> = proc_tgids.difference(proc_tgids_libc).copied().collect();
    if !hidden_by_libc.is_empty() {
        let should_emit = channel_cd.hook_last_emitted == 0
            || now.saturating_sub(channel_cd.hook_last_emitted) > ALERT_COOLDOWN_NANOS;
        if should_emit {
            channel_cd.hook_last_emitted = now;
            out.push(Detection {
                class: DetectionClass::Hook,
                tgid: 0,
                elapsed: 0,
                details: format!(
                    "{} PID(s) hidden from libc readdir — LD_PRELOAD rootkit suspected",
                    hidden_by_libc.len()
                ),
            });
        }
    } else {
        channel_cd.hook_last_emitted = 0;
    }

    // 3. Channel-level SILENT checks.
    // The scheduler is never empty on a running Linux system (init, kernel
    // threads, timer ticks, I/O waiters). If max(sched_last) is stale beyond
    // CHANNEL_DEAD_NANOS while /proc is non-empty, the sched channel is dead.
    // If max_sched == 0 and we're past CHANNEL_DEAD_NANOS, sched never fired.

    let max_sched = registry.values().map(|r| r.sched_last).max().unwrap_or(0);
    let sched_stale = if max_sched == 0 { now } else { now.saturating_sub(max_sched) };

    if !proc_tgids.is_empty() && sched_stale > CHANNEL_DEAD_NANOS {
        let should_emit = channel_cd.sched_silent_last == 0
            || now.saturating_sub(channel_cd.sched_silent_last) > ALERT_COOLDOWN_NANOS;
        if should_emit {
            channel_cd.sched_silent_last = now;
            out.push(Detection {
                class: DetectionClass::Silent,
                tgid: 0,
                elapsed: sched_stale,
                details: format!(
                    "sched_switch channel silent ({:.1}s)", sched_stale as f64 / 1e9
                ),
            });
        }
    } else {
        channel_cd.sched_silent_last = 0;
    }

    // NMI channel death: no heartbeat event for >CHANNEL_DEAD_NANOS.
    // last_nmi_hb == 0 means never heard from; sched_stale provides the
    // grace period (if now < CHANNEL_DEAD_NANOS, we're still starting up).
    let nmi_stale = if last_nmi_hb == 0 { now } else { now.saturating_sub(last_nmi_hb) };

    if nmi_stale > CHANNEL_DEAD_NANOS {
        let should_emit = channel_cd.nmi_silent_last == 0
            || now.saturating_sub(channel_cd.nmi_silent_last) > ALERT_COOLDOWN_NANOS;
        if should_emit {
            channel_cd.nmi_silent_last = now;
            out.push(Detection {
                class: DetectionClass::Silent,
                tgid: 0,
                elapsed: nmi_stale,
                details: format!(
                    "NMI channel silent ({:.1}s)", nmi_stale as f64 / 1e9
                ),
            });
        }
    } else {
        channel_cd.nmi_silent_last = 0;
    }

    // 3. Per-record evaluation.
    for (&tgid, record) in registry.iter_mut() {
        // Grace window: skip freshly-forked / freshly-seeded records so they
        // don't fire before the channels have had a chance to observe them.
        if now.wrapping_sub(record.first_seen) < GRACE_WINDOW_NANOS {
            continue;
        }

        let in_proc    = proc_tgids.contains(&tgid);
        let sched_live = record.sched_last != 0 && now.wrapping_sub(record.sched_last) < SCHED_LIVENESS_NANOS;

        for class in ProcessClass::ALL {
            let (predicate, threshold, details) = match class {
                ProcessClass::Dkom => (
                    !in_proc && sched_live,
                    SUSPECT_THRESHOLD_NANOS,
                    format!("hidden {:.1}s", now.saturating_sub(
                        record.classes[class as usize].suspect_since) as f64 / 1e9),
                ),
                ProcessClass::Ghost => (
                    in_proc && record.sched_last == 0,
                    GHOST_THRESHOLD_NANOS,
                    "present in /proc, never seen by sched".to_string(),
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

    // 4. Eviction: drop records that are stale on sched AND not in /proc.
    registry.retain(|&tgid, record| {
        let sched_age = if record.sched_last == 0 { u64::MAX } else { now.saturating_sub(record.sched_last) };
        sched_age < STALE_NANOS || proc_tgids.contains(&tgid)
    });
}

// ── Event handlers ───────────────────────────────────────────────────────────

/// Called when a sched_switch event arrives. Updates `sched_last` on the
/// record and checks for DUPE (start_time_ns mismatch — same TGID, different
/// kernel birth timestamp). Returns Some(DUPE) if detected, else None.
///
/// **Time-base fix:** `sched_last` stores `now` (process-local nanos), NOT
/// `info.last_seen` (which is bpf_ktime_get_ns() — kernel boot nanos). Mixing
/// time bases caused all liveness predicates to silently fail in earlier
/// versions. See README §11 (The BTF Bug Incident).
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
        record.sched_last = now;
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

    record.sched_last = now;
    None
}

/// Called when an LKM load attempt event arrives. Always returns a Detection
/// (either LkmAllow during boot window or LkmDeny after gate locked). There's
/// no "no-op" outcome — every READING_MODULE intercept emits something.
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

    // ── Type-level sanity tests ───────────────────────────────────────────────

    #[test]
    fn process_record_is_56_bytes() {
        assert_eq!(std::mem::size_of::<ProcessRecord>(), 56);
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
    fn process_class_to_detection_class_covers_variants() {
        assert_eq!(ProcessClass::Dkom.to_detection_class(),  DetectionClass::Dkm);
        assert_eq!(ProcessClass::Ghost.to_detection_class(), DetectionClass::Ghost);
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
        for c in ProcessClass::ALL {
            assert_eq!(rec.classes[c as usize].suspect_since, 0);
            assert_eq!(rec.classes[c as usize].last_emitted, 0);
        }
    }

    #[test]
    fn process_record_seeded_marks_sched_seen() {
        let rec = ProcessRecord::seeded(5000);
        assert_eq!(rec.first_seen, 5000);
        assert_eq!(rec.sched_last, 5000);  // seeded as observed
    }

    #[test]
    fn process_record_seeded_handles_zero_now() {
        let rec = ProcessRecord::seeded(0);
        assert_eq!(rec.first_seen, 1);  // max(1) guard
        assert_eq!(rec.sched_last, 1);  // also max(1) guarded
    }

    // ── evaluate() per-record FSM tests ──────────────────────────────────────

    #[test]
    fn dkom_fires_when_scheduled_but_absent_from_proc() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let now = 5_000_000_000;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = now - 100_000_000;  // alive (100ms < 500ms liveness)
        rec.classes[ProcessClass::Dkom as usize].suspect_since =
            now - SUSPECT_THRESHOLD_NANOS - 1;
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new();
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, &proc_tgids, now, 0, &mut cd, &mut out);
        assert!(out.iter().any(|d| d.class == DetectionClass::Dkm),
            "expected DKOM, got: {:?}", out);
    }

    #[test]
    fn dkom_respects_grace_window() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let now = 100u64;
        let mut rec = ProcessRecord::new(0, now);
        rec.sched_last = now;
        rec.classes[ProcessClass::Dkom as usize].suspect_since = 1;
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new();
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        let tick = now + GRACE_WINDOW_NANOS - 1;
        evaluate(&mut reg, &proc_tgids, &proc_tgids, tick, 0, &mut cd, &mut out);
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
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        // Tick 1: fires. Pass last_nmi_hb=t1 to keep NMI channel alive.
        evaluate(&mut reg, &proc_tgids, &proc_tgids, t1, t1, &mut cd, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].class, DetectionClass::Dkm);
        out.clear();

        // Tick 2 within cooldown — no re-fire. Keep sched + NMI alive.
        let t2 = t1 + 1_000_000;
        reg.get_mut(&tgid).unwrap().sched_last = t2;
        evaluate(&mut reg, &proc_tgids, &proc_tgids, t2, t2, &mut cd, &mut out);
        assert!(out.is_empty(), "no re-fire within cooldown");
        out.clear();

        // Tick 3 past cooldown — re-fires
        let t3 = t1 + ALERT_COOLDOWN_NANOS + 1;
        reg.get_mut(&tgid).unwrap().sched_last = t3;
        evaluate(&mut reg, &proc_tgids, &proc_tgids, t3, t3, &mut cd, &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn dkom_clears_when_process_reappears_in_proc() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1;
        rec.classes[ProcessClass::Dkom as usize].suspect_since = 100;
        rec.classes[ProcessClass::Dkom as usize].last_emitted = 200;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        let now = 100_000_000;
        evaluate(&mut reg, &proc_tgids, &proc_tgids, now, 0, &mut cd, &mut out);

        assert!(out.is_empty());
        let cs = &reg.get(&tgid).unwrap().classes[ProcessClass::Dkom as usize];
        assert_eq!(cs.suspect_since, 0);
        assert_eq!(cs.last_emitted, 0);
    }

    #[test]
    fn ghost_fires_when_in_proc_never_observed_by_sched() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let now = 10_000_000_000;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 0;  // never seen by sched
        rec.classes[ProcessClass::Ghost as usize].suspect_since =
            now - GHOST_THRESHOLD_NANOS - 1;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, &proc_tgids, now, 0, &mut cd, &mut out);
        assert!(out.iter().any(|d| d.class == DetectionClass::Ghost),
            "expected GHOST, got: {:?}", out);
    }

    // ── evaluate() channel-level SILENT tests ────────────────────────────────

    #[test]
    fn silent_fires_when_sched_channel_dead() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1_000_000_000;  // stale
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);  // /proc non-empty
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        let now = 1_000_000_000 + CHANNEL_DEAD_NANOS + 1;  // past threshold
        evaluate(&mut reg, &proc_tgids, &proc_tgids, now, 0, &mut cd, &mut out);
        assert!(out.iter().any(|d| d.class == DetectionClass::Silent),
            "expected SILENT for dead sched channel, got: {:?}", out);
    }

    #[test]
    fn silent_fires_when_nmi_channel_dead() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 10_000_000_000;  // fresh (avoids sched-silent)
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        let now = 10_000_000_000;
        let last_nmi = 1_000_000_000u64;  // NMI heartbeat very stale
        evaluate(&mut reg, &proc_tgids, &proc_tgids, now, last_nmi, &mut cd, &mut out);
        assert!(out.iter().any(|d| d.class == DetectionClass::Silent
            && d.details.contains("NMI")),
            "expected SILENT for dead NMI channel, got: {:?}", out);
    }

    #[test]
    fn silent_does_not_fire_during_grace_period() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 0;  // never seen
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        // now is small — within grace period
        let now = 1_000_000_000;  // 1 sec < CHANNEL_DEAD_NANOS (5 sec)
        evaluate(&mut reg, &proc_tgids, &proc_tgids, now, 0, &mut cd, &mut out);
        assert!(out.is_empty(), "no SILENT during grace period");
    }

    #[test]
    fn silent_respects_cooldown() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1_000_000_000;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        let now = 1_000_000_000 + CHANNEL_DEAD_NANOS + 1;

        // Tick 1: fires
        evaluate(&mut reg, &proc_tgids, &proc_tgids, now, 0, &mut cd, &mut out);
        assert!(out.iter().any(|d| d.class == DetectionClass::Silent));
        out.clear();

        // Tick 2 within cooldown — no re-fire
        evaluate(&mut reg, &proc_tgids, &proc_tgids, now + 1_000_000, 0, &mut cd, &mut out);
        assert!(out.is_empty(), "no re-fire within cooldown");
    }

    #[test]
    fn silent_clears_when_channel_recovers() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1_000_000_000;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        let now_dead = 1_000_000_000 + CHANNEL_DEAD_NANOS + 1;
        evaluate(&mut reg, &proc_tgids, &proc_tgids, now_dead, 0, &mut cd, &mut out);
        assert!(!out.is_empty());
        assert!(cd.sched_silent_last != 0);
        out.clear();

        // Channel recovers — sched_last is fresh now
        let now_alive = now_dead + 1_000_000;
        reg.get_mut(&tgid).unwrap().sched_last = now_alive;
        evaluate(&mut reg, &proc_tgids, &proc_tgids, now_alive, 0, &mut cd, &mut out);
        assert!(out.is_empty(), "no SILENT when channel recovers");
        assert_eq!(cd.sched_silent_last, 0, "cooldown reset on recovery");
    }

    #[test]
    fn silent_does_not_fire_when_proc_is_empty() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1;  // very stale
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new();  // /proc empty — can't prove system is live
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        let now = CHANNEL_DEAD_NANOS + 10;
        evaluate(&mut reg, &proc_tgids, &proc_tgids, now, 0, &mut cd, &mut out);
        // SILENT should not fire because /proc is empty (the liveness guard)
        assert!(out.iter().all(|d| d.class != DetectionClass::Silent
            || !d.details.contains("sched")),
            "sched SILENT should not fire when /proc is empty");
    }

    // ── Eviction tests ───────────────────────────────────────────────────────

    #[test]
    fn evaluate_evicts_records_stale_on_sched_and_not_in_proc() {
        let mut reg = ProcessRegistry::new();
        let tgid = 9999u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1;
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new();
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, &proc_tgids, STALE_NANOS + 1, 0, &mut cd, &mut out);
        assert!(!reg.contains_key(&tgid), "stale record should be evicted");
    }

    #[test]
    fn evaluate_retains_records_that_are_in_proc_even_if_stale() {
        let mut reg = ProcessRegistry::new();
        let tgid = 9999u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, &proc_tgids, STALE_NANOS + 1, 0, &mut cd, &mut out);
        assert!(reg.contains_key(&tgid), "in-proc record should be retained");
    }

    #[test]
    fn evaluate_does_not_reallocate_out_when_empty() {
        let mut reg = ProcessRegistry::new();
        let proc_tgids = HashSet::new();
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, &proc_tgids, 0, 0, &mut cd, &mut out);
        assert_eq!(out.len(), 0);

        // Re-run — capacity should remain 0
        evaluate(&mut reg, &proc_tgids, &proc_tgids, 1_000_000_000, 0, &mut cd, &mut out);
        assert_eq!(out.capacity(), 0, "no growth on empty re-run");
    }

    // ── HOOK detection tests ─────────────────────────────────────────────────

    #[test]
    fn hook_fires_when_libc_readdir_hides_pids() {
        let mut reg = ProcessRegistry::new();
        let now = 10_000_000_000u64;

        let mut proc_tgids = HashSet::new();
        proc_tgids.extend([1, 2, 3, 4, 5]);

        // libc readdir sees only {1,2,3} — LD_PRELOAD rootkit hides 4,5
        let mut proc_tgids_libc = HashSet::new();
        proc_tgids_libc.extend([1, 2, 3]);

        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, &proc_tgids_libc, now, now, &mut cd, &mut out);
        assert!(
            out.iter().any(|d| d.class == DetectionClass::Hook),
            "expected HOOK, got: {:?}",
            out
        );
    }

    #[test]
    fn hook_does_not_fire_when_sets_match() {
        let mut reg = ProcessRegistry::new();
        let now = 10_000_000_000u64;

        let mut proc_tgids = HashSet::new();
        proc_tgids.extend([1, 2, 3]);
        let proc_tgids_libc = proc_tgids.clone();

        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        evaluate(&mut reg, &proc_tgids, &proc_tgids_libc, now, now, &mut cd, &mut out);
        assert!(
            out.iter().all(|d| d.class != DetectionClass::Hook),
            "HOOK should not fire when sets match"
        );
    }

    #[test]
    fn hook_respects_cooldown() {
        let mut reg = ProcessRegistry::new();
        let t1 = 10_000_000_000u64;

        let mut proc_tgids = HashSet::new();
        proc_tgids.extend([1, 2]);
        let mut proc_tgids_libc = HashSet::new();
        proc_tgids_libc.insert(1); // PID 2 hidden

        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        // Tick 1: HOOK fires
        evaluate(&mut reg, &proc_tgids, &proc_tgids_libc, t1, t1, &mut cd, &mut out);
        assert!(out.iter().any(|d| d.class == DetectionClass::Hook));
        out.clear();

        // Tick 2 within cooldown — no re-fire
        let t2 = t1 + 1_000_000;
        evaluate(&mut reg, &proc_tgids, &proc_tgids_libc, t2, t2, &mut cd, &mut out);
        assert!(out.is_empty(), "no re-fire within cooldown");
    }

    // ── on_sched_event / DUPE tests ──────────────────────────────────────────

    fn proc_info(tgid: u32, start_time: u64, _last_seen: u64) -> ProcessInfo {
        ProcessInfo {
            pid: tgid, tgid, comm: [0u8; 16],
            last_seen: _last_seen, start_time_ns: start_time, cpu: 0, event_type: 0,
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
        assert_eq!(rec.sched_last, 5000);  // process-local time, not ktime
    }

    #[test]
    fn on_sched_event_fires_dupe_on_start_time_mismatch() {
        let mut reg = ProcessRegistry::new();
        reg.insert(1234, ProcessRecord::new(999, 0));

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
        reg.insert(1234, ProcessRecord::new(0, 0));

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

    #[test]
    fn on_sched_event_stores_process_local_time_not_ktime() {
        // Regression test for the time-base bug (README §11).
        // sched_last must store the `now` parameter (process-local nanos),
        // NOT info.last_seen (bpf_ktime_get_ns — kernel boot nanos).
        let mut reg = ProcessRegistry::new();
        let info = proc_info(1234, 0, 9_999_999_999_999);  // ktime-ish value
        on_sched_event(info, &mut reg, 5_000);  // process-local time

        let rec = reg.get(&1234).unwrap();
        assert_eq!(rec.sched_last, 5_000, "sched_last must be process-local time");
        assert_ne!(rec.sched_last, 9_999_999_999_999, "sched_last must NOT be ktime");
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

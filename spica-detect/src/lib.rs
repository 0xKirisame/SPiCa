//! SPiCa detection FSM — pure logic, no I/O.
//!
//! All functions here are deterministic over their inputs (ProcessRegistry,
//! /proc tgids, current time). No file reads, no printing, no eBPF. This
//! module is the testable surface of SPiCa's detection logic — every other
//! module feeds it data and consumes its output.

use std::collections::{HashMap, HashSet, VecDeque};

use spica_common::{LedgerRecord, NotaryEvent, chain_hash};

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
    PcrDiverge, // TPM PCR value diverged from the daemon's mirror
    Inject,     // libc readdir reporting entries the kernel doesn't have
}

impl DetectionClass {
    /// Uppercased label for the alert line, e.g. `DKOM`, `LKM-DENY`.
    pub fn label(self) -> &'static str {
        match self {
            DetectionClass::Dkm => "DKOM",
            DetectionClass::Ghost => "GHOST",
            DetectionClass::Tamper => "TAMPER",
            DetectionClass::Silent => "SILENT",
            DetectionClass::Dupe => "DUPE",
            DetectionClass::LkmAllow => "LKM-ALLOW",
            DetectionClass::LkmDeny => "LKM-DENY",
            DetectionClass::Watchdog => "WATCHDOG",
            DetectionClass::Hook => "HOOK",
            DetectionClass::PcrDiverge => "PCR-DIVERGE",
            DetectionClass::Inject => "INJECT",
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
            ProcessClass::Dkom => DetectionClass::Dkm,
            ProcessClass::Ghost => DetectionClass::Ghost,
        }
    }

    /// All variants in array-index order. Used by evaluate() to iterate.
    pub const ALL: [ProcessClass; ProcessClass::COUNT] = [ProcessClass::Dkom, ProcessClass::Ghost];
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
    pub suspect_since: u64, // nanos since process epoch; 0 = not suspect
    pub last_emitted: u64,  // nanos since process epoch; 0 = never emitted
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
    pub start_time_ns: u64,                         // 8  (kernel task birth time)
    pub first_seen: u64,                            // 8  (nanos since process epoch)
    pub sched_last: u64,                            // 8  (nanos since epoch; 0 = never)
    pub classes: [ClassState; ProcessClass::COUNT], // 32 (2 x 16)
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
            classes: [ClassState {
                suspect_since: 0,
                last_emitted: 0,
            }; ProcessClass::COUNT],
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
            classes: [ClassState {
                suspect_since: 0,
                last_emitted: 0,
            }; ProcessClass::COUNT],
        }
    }
}

/// The registry of all currently-tracked processes, keyed by TGID.
pub type ProcessRegistry = HashMap<u32, ProcessRecord>;

/// Channel-level cooldown state for SILENT alerts. Owned by the caller
/// (main.rs) and passed mutably to evaluate() across ticks.
#[derive(Debug, Clone, Default)]
pub struct ChannelCooldown {
    /// Last emit time for sched-channel SILENT (0 = never emitted / recovered).
    pub sched_silent_last: u64,
    /// Last emit time for NMI-channel SILENT (0 = never emitted / recovered).
    pub nmi_silent_last: u64,
    /// Last emit time for HOOK alerts (0 = never emitted / recovered).
    pub hook_last_emitted: u64,
    /// Last emit time for INJECT alerts (0 = never emitted / recovered).
    pub inject_last_emitted: u64,
    /// PID sets seen once and awaiting a confirming second tick. A single
    /// discrepancy between the two /proc lenses can be a benign read race
    /// (a process forking/exiting between them) — only a set that persists
    /// across consecutive ticks is an alert.
    pub hook_pending: Vec<u32>,
    pub inject_pending: Vec<u32>,
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

pub const TICK_RATE_MS: u64 = 100;
pub const SUSPECT_THRESHOLD_NANOS: u64 = 2_000_000_000; // 2 sec
pub const GHOST_THRESHOLD_NANOS: u64 = 5_000_000_000; // 5 sec
pub const ALERT_COOLDOWN_NANOS: u64 = 30_000_000_000; // 30 sec
pub const GRACE_WINDOW_NANOS: u64 = 50_000_000; // 50 ms
pub const STALE_NANOS: u64 = 10_000_000_000; // 10 sec
pub const SCHED_LIVENESS_NANOS: u64 = 500_000_000; // 500 ms
pub const CHANNEL_DEAD_NANOS: u64 = 5_000_000_000; // 5 sec — channel-level death

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
        registry
            .entry(tgid)
            .or_insert_with(|| ProcessRecord::seeded(now));
    }

    // 2. Unified three-view differential, C lens: the R/C pair reads the
    // same kernel object through two lenses — raw getdents64 (R, unhookable)
    // and libc readdir (C, what every tool sees). Both directions of the
    // difference are detections, processed in the same pass:
    //   R ∖ C → HOOK   (libc hides a real process: LD_PRELOAD rootkit)
    //   C ∖ R → INJECT (libc fabricates a process the kernel doesn't have)
    let hidden_by_libc: Vec<u32> = {
        let mut v: Vec<u32> = proc_tgids.difference(proc_tgids_libc).copied().collect();
        v.sort_unstable();
        v
    };
    let hook_stable = hidden_by_libc == channel_cd.hook_pending;
    channel_cd.hook_pending = hidden_by_libc.clone();
    if !hidden_by_libc.is_empty() && hook_stable {
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
    }
    if hidden_by_libc.is_empty() {
        // Discrepancy resolved — reset cooldown and pending set.
        channel_cd.hook_last_emitted = 0;
        channel_cd.hook_pending.clear();
    }

    let injected_by_libc: Vec<u32> = {
        let mut v: Vec<u32> = proc_tgids_libc.difference(proc_tgids).copied().collect();
        v.sort_unstable();
        v
    };
    let inject_stable = injected_by_libc == channel_cd.inject_pending;
    channel_cd.inject_pending = injected_by_libc.clone();
    if !injected_by_libc.is_empty() && inject_stable {
        let should_emit = channel_cd.inject_last_emitted == 0
            || now.saturating_sub(channel_cd.inject_last_emitted) > ALERT_COOLDOWN_NANOS;
        if should_emit {
            channel_cd.inject_last_emitted = now;
            out.push(Detection {
                class: DetectionClass::Inject,
                tgid: 0,
                elapsed: 0,
                details: format!(
                    "{} PID(s) reported by libc readdir but absent from raw getdents64 — fabricated process entries (rootkit blending) suspected",
                    injected_by_libc.len()
                ),
            });
        }
    }
    if injected_by_libc.is_empty() {
        channel_cd.inject_last_emitted = 0;
        channel_cd.inject_pending.clear();
    }

    // 3. Channel-level SILENT checks.
    // The scheduler is never empty on a running Linux system (init, kernel
    // threads, timer ticks, I/O waiters). If max(sched_last) is stale beyond
    // CHANNEL_DEAD_NANOS while /proc is non-empty, the sched channel is dead.
    // If max_sched == 0 and we're past CHANNEL_DEAD_NANOS, sched never fired.

    let max_sched = registry.values().map(|r| r.sched_last).max().unwrap_or(0);
    let sched_stale = if max_sched == 0 {
        now
    } else {
        now.saturating_sub(max_sched)
    };

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
                    "sched_switch channel silent ({:.1}s)",
                    sched_stale as f64 / 1e9
                ),
            });
        }
    } else {
        channel_cd.sched_silent_last = 0;
    }

    // NMI channel death: no heartbeat event for >CHANNEL_DEAD_NANOS.
    // last_nmi_hb == 0 means never heard from; sched_stale provides the
    // grace period (if now < CHANNEL_DEAD_NANOS, we're still starting up).
    let nmi_stale = if last_nmi_hb == 0 {
        now
    } else {
        now.saturating_sub(last_nmi_hb)
    };

    if nmi_stale > CHANNEL_DEAD_NANOS {
        let should_emit = channel_cd.nmi_silent_last == 0
            || now.saturating_sub(channel_cd.nmi_silent_last) > ALERT_COOLDOWN_NANOS;
        if should_emit {
            channel_cd.nmi_silent_last = now;
            out.push(Detection {
                class: DetectionClass::Silent,
                tgid: 0,
                elapsed: nmi_stale,
                details: format!("NMI channel silent ({:.1}s)", nmi_stale as f64 / 1e9),
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

        let in_proc = proc_tgids.contains(&tgid);
        let sched_live =
            record.sched_last != 0 && now.wrapping_sub(record.sched_last) < SCHED_LIVENESS_NANOS;

        for class in ProcessClass::ALL {
            let (predicate, threshold, details) = match class {
                ProcessClass::Dkom => (
                    !in_proc && sched_live,
                    SUSPECT_THRESHOLD_NANOS,
                    format!(
                        "hidden {:.1}s",
                        now.saturating_sub(record.classes[class as usize].suspect_since) as f64
                            / 1e9
                    ),
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
        let sched_age = if record.sched_last == 0 {
            u64::MAX
        } else {
            now.saturating_sub(record.sched_last)
        };
        sched_age < STALE_NANOS || proc_tgids.contains(&tgid)
    });
}

// ── Ledger chain verification ────────────────────────────────────────────────

/// How many recent (seq, head) pairs are retained per CPU for notary
/// cross-checks. Notary snapshots race in-flight appends, so a snapshot may
/// legitimately lag the local chain by a few entries; this window must be
/// wide enough that only genuine suppression/editing falls outside it.
const CHAIN_HISTORY: usize = 256;

/// Per-CPU chain position as reconstructed from the transport ring buffer.
#[derive(Debug, Clone)]
struct CpuChain {
    /// Sequence of the last verified record (0 = none yet).
    seq: u64,
    /// Chain head at that sequence.
    head: u64,
    /// Recent (seq, head) pairs, oldest first, bounded to CHAIN_HISTORY.
    history: VecDeque<(u64, u64)>,
    /// A notary snapshot that was ahead of the local chain, awaiting
    /// confirmation (0 = none pending). One-notary-ahead is a benign race —
    /// the snapshot lands between the record write and ring-buffer
    /// consumption (observed live under QEMU: seq off-by-one false
    /// TAMPERs). Two consecutive notaries with the chain still behind is
    /// suppression: in-flight records always arrive within a second;
    /// suppressed ones never do.
    pending_notary_seq: u64,
}

impl CpuChain {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            seq: 0,
            head: 0,
            history: VecDeque::new(),
            pending_notary_seq: 0,
        }
    }

    fn advance(&mut self, rec: &LedgerRecord) {
        self.seq = rec.seq;
        self.head = chain_hash(rec.prev_head, rec.seq, rec);
        self.history.push_back((self.seq, self.head));
        while self.history.len() > CHAIN_HISTORY {
            self.history.pop_front();
        }
    }
}

/// Tracks the per-CPU hash chains reconstructed from ledger records and
/// cross-checks NMI notary snapshots against them.
///
/// This is the userspace half of the ledger integrity model: the eBPF side
/// appends `chain_hash`-linked records; this side recomputes every link and
/// flags gaps (suppression) and divergent heads (editing) as TAMPER.
#[derive(Debug, Default)]
pub struct ChainTracker {
    per_cpu: HashMap<u32, CpuChain>,
    /// Process-local nanos of the last verified record (any CPU). Used for
    /// channel-level stall detection.
    pub last_record: u64,
}

impl ChainTracker {
    /// Verified per-CPU chain positions `(cpu, seq, head)`, sorted by cpu —
    /// the exact state the PCR anchor commits to each epoch. Only positions
    /// that passed verification are included: the anchor extends the
    /// daemon's *trusted* view, never raw observations.
    pub fn snapshot(&self) -> Vec<(u32, u64, u64)> {
        let mut v: Vec<(u32, u64, u64)> = self
            .per_cpu
            .iter()
            .map(|(&cpu, cc)| (cpu, cc.seq, cc.head))
            .collect();
        v.sort_unstable_by_key(|&(cpu, _, _)| cpu);
        v
    }
}

/// Verify one ledger record against its per-CPU chain, update the process
/// registry, and return TAMPER on any discontinuity.
///
/// Verification rules (per CPU):
/// - first record seen: adopted as the chain starting point (the transport
///   may begin mid-stream)
/// - `rec.seq != local.seq + 1` → gap → a record was suppressed in transit
/// - `rec.prev_head != local.head` at a contiguous seq → divergence → a
///   record's content was edited in transit
///
/// After any TAMPER the chain resynchronizes at the offending record so one
/// incident produces exactly one alert (not an alert storm).
pub fn on_ledger_event(
    rec: LedgerRecord,
    resolved_tgid: Option<u32>,
    chain: &mut ChainTracker,
    registry: &mut ProcessRegistry,
    now: u64,
) -> Option<Detection> {
    let cc = chain.per_cpu.entry(rec.cpu).or_insert_with(|| CpuChain {
        // Adopt the parent position implied by the first record.
        seq: rec.seq.saturating_sub(1),
        head: rec.prev_head,
        history: VecDeque::new(),
        pending_notary_seq: 0,
    });

    let mut detection = None;
    if cc.seq != 0 && rec.seq != cc.seq + 1 {
        detection = Some(Detection {
            class: DetectionClass::Tamper,
            tgid: 0,
            elapsed: 0,
            details: format!(
                "ledger chain gap on cpu{}: expected seq {}, got {} — records suppressed in transit",
                rec.cpu,
                cc.seq + 1,
                rec.seq
            ),
        });
    } else if cc.seq != 0 && rec.prev_head != cc.head {
        detection = Some(Detection {
            class: DetectionClass::Tamper,
            tgid: 0,
            elapsed: 0,
            details: format!(
                "ledger chain divergence on cpu{} at seq {}: expected prev_head {:#018x}, got {:#018x} — records edited in transit",
                rec.cpu, rec.seq, cc.head, rec.prev_head
            ),
        });
    }
    cc.advance(&rec);
    chain.last_record = now;

    // Registry update: heartbeats (tgid == 0) carry no process sighting.
    // SWITCH records carry a thread ID as pid/tgid — the caller supplies the
    // /proc-resolved TGID separately so the record stays pristine for the
    // chain hash (mutating it here desynced the chain in the first VM run).
    // FORK/EXIT records carry TGIDs directly from the tracepoint.
    let reg_tgid = resolved_tgid.unwrap_or(rec.tgid);
    if reg_tgid != 0 {
        let record = registry
            .entry(reg_tgid)
            .or_insert_with(|| ProcessRecord::new(0, now));
        record.sched_last = now;
    }

    detection
}

/// Cross-check one NMI notary snapshot against the locally reconstructed
/// chain. A snapshot that is *ahead* of the local chain proves records were
/// suppressed; a head mismatch at a known seq proves records were edited.
/// Stale-but-forgotten snapshots (aged out of the history window) are not
/// provable anomalies and are ignored.
pub fn on_notary_event(ev: NotaryEvent, chain: &mut ChainTracker, now: u64) -> Option<Detection> {
    let _ = now;
    let Some(cc) = chain.per_cpu.get_mut(&ev.cpu) else {
        return None; // no records observed from this CPU yet
    };
    if let Some(&(_, head)) = cc.history.iter().rev().find(|(s, _)| *s == ev.seq) {
        if head != ev.head {
            return Some(Detection {
                class: DetectionClass::Tamper,
                tgid: 0,
                elapsed: 0,
                details: format!(
                    "NMI notary mismatch on cpu{} at seq {}: kernel head {:#018x} != local {:#018x} — transport edited",
                    ev.cpu, ev.seq, ev.head, head
                ),
            });
        }
        return None;
    }
    if ev.seq > cc.seq {
        // Tentative: the snapshot may race an in-flight append (observed
        // live as a benign off-by-one under QEMU). Confirm at the NEXT
        // notary — in-flight records always arrive within a second;
        // suppressed ones never do.
        let confirmed = cc.pending_notary_seq != 0 && cc.seq < cc.pending_notary_seq;
        cc.pending_notary_seq = ev.seq;
        if confirmed {
            return Some(Detection {
                class: DetectionClass::Tamper,
                tgid: 0,
                elapsed: 0,
                details: format!(
                    "NMI notary ahead of chain on cpu{} across consecutive snapshots: kernel seq {} > local {} — records suppressed",
                    ev.cpu, ev.seq, cc.seq
                ),
            });
        }
        return None; // awaiting next notary
    }
    cc.pending_notary_seq = 0; // at or behind the chain: nothing pending
    None
}

// ── Event handlers ───────────────────────────────────────────────────────────

/// Called when an LKM load attempt event arrives. Always returns a Detection
/// (either LkmAllow during boot window or LkmDeny after gate locked). There's
/// no "no-op" outcome — every READING_MODULE intercept emits something.
pub fn on_lkm_event(ev: spica_common::LkmEvent) -> Detection {
    let class = if ev.allowed == 1 {
        DetectionClass::LkmAllow
    } else {
        DetectionClass::LkmDeny
    };
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
        assert_eq!(ProcessClass::Dkom.to_detection_class(), DetectionClass::Dkm);
        assert_eq!(
            ProcessClass::Ghost.to_detection_class(),
            DetectionClass::Ghost
        );
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
        assert_eq!(rec.sched_last, 5000); // seeded as observed
    }

    #[test]
    fn process_record_seeded_handles_zero_now() {
        let rec = ProcessRecord::seeded(0);
        assert_eq!(rec.first_seen, 1); // max(1) guard
        assert_eq!(rec.sched_last, 1); // also max(1) guarded
    }

    // ── evaluate() per-record FSM tests ──────────────────────────────────────

    #[test]
    fn dkom_fires_when_scheduled_but_absent_from_proc() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let now = 5_000_000_000;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = now - 100_000_000; // alive (100ms < 500ms liveness)
        rec.classes[ProcessClass::Dkom as usize].suspect_since = now - SUSPECT_THRESHOLD_NANOS - 1;
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new();
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now,
            0,
            &mut cd,
            &mut out,
        );
        assert!(
            out.iter().any(|d| d.class == DetectionClass::Dkm),
            "expected DKOM, got: {:?}",
            out
        );
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
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            tick,
            0,
            &mut cd,
            &mut out,
        );
        assert!(out.is_empty(), "no alerts during grace window");
    }

    #[test]
    fn dkom_respects_cooldown() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let t1 = 5_000_000_000u64;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = t1;
        rec.classes[ProcessClass::Dkom as usize].suspect_since = t1 - SUSPECT_THRESHOLD_NANOS - 1;
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new();
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        // Tick 1: fires. Pass last_nmi_hb=t1 to keep NMI channel alive.
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            t1,
            t1,
            &mut cd,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].class, DetectionClass::Dkm);
        out.clear();

        // Tick 2 within cooldown — no re-fire. Keep sched + NMI alive.
        let t2 = t1 + 1_000_000;
        reg.get_mut(&tgid).unwrap().sched_last = t2;
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            t2,
            t2,
            &mut cd,
            &mut out,
        );
        assert!(out.is_empty(), "no re-fire within cooldown");
        out.clear();

        // Tick 3 past cooldown — re-fires
        let t3 = t1 + ALERT_COOLDOWN_NANOS + 1;
        reg.get_mut(&tgid).unwrap().sched_last = t3;
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            t3,
            t3,
            &mut cd,
            &mut out,
        );
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
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now,
            0,
            &mut cd,
            &mut out,
        );

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
        rec.sched_last = 0; // never seen by sched
        rec.classes[ProcessClass::Ghost as usize].suspect_since = now - GHOST_THRESHOLD_NANOS - 1;
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now,
            0,
            &mut cd,
            &mut out,
        );
        assert!(
            out.iter().any(|d| d.class == DetectionClass::Ghost),
            "expected GHOST, got: {:?}",
            out
        );
    }

    // ── evaluate() channel-level SILENT tests ────────────────────────────────

    #[test]
    fn silent_fires_when_sched_channel_dead() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1_000_000_000; // stale
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid); // /proc non-empty
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        let now = 1_000_000_000 + CHANNEL_DEAD_NANOS + 1; // past threshold
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now,
            0,
            &mut cd,
            &mut out,
        );
        assert!(
            out.iter().any(|d| d.class == DetectionClass::Silent),
            "expected SILENT for dead sched channel, got: {:?}",
            out
        );
    }

    #[test]
    fn silent_fires_when_nmi_channel_dead() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 10_000_000_000; // fresh (avoids sched-silent)
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        let now = 10_000_000_000;
        let last_nmi = 1_000_000_000u64; // NMI heartbeat very stale
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now,
            last_nmi,
            &mut cd,
            &mut out,
        );
        assert!(
            out.iter()
                .any(|d| d.class == DetectionClass::Silent && d.details.contains("NMI")),
            "expected SILENT for dead NMI channel, got: {:?}",
            out
        );
    }

    #[test]
    fn silent_does_not_fire_during_grace_period() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 0; // never seen
        reg.insert(tgid, rec);

        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(tgid);
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        // now is small — within grace period
        let now = 1_000_000_000; // 1 sec < CHANNEL_DEAD_NANOS (5 sec)
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now,
            0,
            &mut cd,
            &mut out,
        );
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
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now,
            0,
            &mut cd,
            &mut out,
        );
        assert!(out.iter().any(|d| d.class == DetectionClass::Silent));
        out.clear();

        // Tick 2 within cooldown — no re-fire
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now + 1_000_000,
            0,
            &mut cd,
            &mut out,
        );
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
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now_dead,
            0,
            &mut cd,
            &mut out,
        );
        assert!(!out.is_empty());
        assert!(cd.sched_silent_last != 0);
        out.clear();

        // Channel recovers — sched_last is fresh now
        let now_alive = now_dead + 1_000_000;
        reg.get_mut(&tgid).unwrap().sched_last = now_alive;
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now_alive,
            0,
            &mut cd,
            &mut out,
        );
        assert!(out.is_empty(), "no SILENT when channel recovers");
        assert_eq!(cd.sched_silent_last, 0, "cooldown reset on recovery");
    }

    #[test]
    fn silent_does_not_fire_when_proc_is_empty() {
        let mut reg = ProcessRegistry::new();
        let tgid = 1234u32;
        let mut rec = ProcessRecord::new(0, 0);
        rec.sched_last = 1; // very stale
        reg.insert(tgid, rec);

        let proc_tgids = HashSet::new(); // /proc empty — can't prove system is live
        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        let now = CHANNEL_DEAD_NANOS + 10;
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            now,
            0,
            &mut cd,
            &mut out,
        );
        // SILENT should not fire because /proc is empty (the liveness guard)
        assert!(
            out.iter()
                .all(|d| d.class != DetectionClass::Silent || !d.details.contains("sched")),
            "sched SILENT should not fire when /proc is empty"
        );
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

        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            STALE_NANOS + 1,
            0,
            &mut cd,
            &mut out,
        );
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

        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            STALE_NANOS + 1,
            0,
            &mut cd,
            &mut out,
        );
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
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids,
            1_000_000_000,
            0,
            &mut cd,
            &mut out,
        );
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

        double_tick(&mut reg, &proc_tgids, &proc_tgids_libc, now, &mut out, &mut cd);
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

        double_tick(&mut reg, &proc_tgids, &proc_tgids_libc, now, &mut out, &mut cd);
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

        // Ticks 1+2: HOOK fires (debounced: needs a stable set)
        double_tick(&mut reg, &proc_tgids, &proc_tgids_libc, t1, &mut out, &mut cd);
        assert!(out.iter().any(|d| d.class == DetectionClass::Hook));
        out.clear();

        // Tick 2 within cooldown — no re-fire
        let t2 = t1 + 1_000_000;
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids_libc,
            t2,
            t2,
            &mut cd,
            &mut out,
        );
        assert!(out.is_empty(), "no re-fire within cooldown");
    }

    /// Two-tick helper: the C-lens verdicts debounce /proc read races, so a
    /// discrepancy must persist across consecutive ticks before alerting.
    fn double_tick(
        reg: &mut ProcessRegistry,
        raw: &HashSet<u32>,
        libc: &HashSet<u32>,
        t1: u64,
        out: &mut Vec<Detection>,
        cd: &mut ChannelCooldown,
    ) {
        let raw2 = raw.clone();
        let libc2 = libc.clone();
        evaluate(reg, raw, libc, t1, t1, cd, out);
        let mut out2 = Vec::new();
        evaluate(reg, &raw2, &libc2, t1 + 10_000_000, t1 + 10_000_000, cd, &mut out2);
        out.extend(out2);
    }

    // ── INJECT detection tests (unified differential, C∖R direction) ────────

    #[test]
    fn inject_fires_when_libc_readdir_fabricates_pids() {
        let mut reg = ProcessRegistry::new();
        let now = 10_000_000_000u64;
        let mut proc_tgids = HashSet::new(); // raw syscall: kernel truth
        proc_tgids.extend([1, 2]);
        let mut proc_tgids_libc = HashSet::new(); // libc: fake extra PID
        proc_tgids_libc.extend([1, 2, 31337]);

        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();
        double_tick(&mut reg, &proc_tgids, &proc_tgids_libc, now, &mut out, &mut cd);
        assert!(
            out.iter().any(|d| d.class == DetectionClass::Inject),
            "expected INJECT, got: {:?}",
            out
        );
    }

    #[test]
    fn inject_does_not_fire_when_sets_match() {
        let mut reg = ProcessRegistry::new();
        let now = 10_000_000_000u64;
        let mut proc_tgids = HashSet::new();
        proc_tgids.extend([1, 2, 3]);
        let proc_tgids_libc = proc_tgids.clone();

        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();
        double_tick(&mut reg, &proc_tgids, &proc_tgids_libc, now, &mut out, &mut cd);
        assert!(out.iter().all(|d| d.class != DetectionClass::Inject));
    }

    #[test]
    fn inject_and_hook_fire_together_when_both_directions_differ() {
        // Full differential: libc hides PID 2 (HOOK) AND fabricates 31337
        // (INJECT) — a rootkit blending and hiding simultaneously.
        let mut reg = ProcessRegistry::new();
        let now = 10_000_000_000u64;
        let mut proc_tgids = HashSet::new();
        proc_tgids.extend([1, 2]);
        let mut proc_tgids_libc = HashSet::new();
        proc_tgids_libc.extend([1, 31337]);

        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();
        double_tick(&mut reg, &proc_tgids, &proc_tgids_libc, now, &mut out, &mut cd);
        assert!(out.iter().any(|d| d.class == DetectionClass::Hook));
        assert!(out.iter().any(|d| d.class == DetectionClass::Inject));
    }

    #[test]
    fn inject_respects_cooldown_and_recovers() {
        let mut reg = ProcessRegistry::new();
        let t1 = 10_000_000_000u64;
        let mut proc_tgids = HashSet::new();
        proc_tgids.insert(1);
        let mut proc_tgids_libc = HashSet::new();
        proc_tgids_libc.extend([1, 31337]);

        let mut cd = ChannelCooldown::default();
        let mut out = Vec::new();

        double_tick(&mut reg, &proc_tgids, &proc_tgids_libc, t1, &mut out, &mut cd);
        assert!(out.iter().any(|d| d.class == DetectionClass::Inject));
        out.clear();

        // Within cooldown — silent
        evaluate(
            &mut reg,
            &proc_tgids,
            &proc_tgids_libc,
            t1 + 1_000_000,
            t1 + 1_000_000,
            &mut cd,
            &mut out,
        );
        assert!(out.is_empty());

        // Recovers — cooldown resets when the sets agree again
        let mut clean = HashSet::new();
        clean.insert(1);
        evaluate(
            &mut reg,
            &clean,
            &clean,
            t1 + 2_000_000,
            t1 + 2_000_000,
            &mut cd,
            &mut out,
        );
        assert_eq!(cd.inject_last_emitted, 0, "cooldown reset on recovery");
    }

    // ── Ledger chain verification tests ─────────────────────────────────────

    use spica_common::{KIND_EXIT, KIND_FORK, KIND_HEARTBEAT, KIND_SWITCH};

    fn ledger_rec(cpu: u32, seq: u64, prev_head: u64, tgid: u32, kind: u32) -> LedgerRecord {
        LedgerRecord {
            pid: tgid,
            tgid,
            cpu,
            kind,
            comm: [0u8; 16],
            ktime_ns: 1_000 * seq,
            seq,
            prev_head,
        }
    }

    /// Build a valid chain of records for `cpu` (each linked to the previous
    /// head), verifying each one through on_ledger_event.
    fn build_chain(cpu: u32, n: u64, chain: &mut ChainTracker, reg: &mut ProcessRegistry) {
        let mut head: u64 = 0;
        for s in 1..=n {
            let rec = ledger_rec(cpu, s, head, (s % 100) as u32, KIND_SWITCH);
            head = chain_hash(head, s, &rec);
            let r = rec; // avoid re-borrow issues
            let _ = on_ledger_event(r, None, chain, reg, 1_000 * s);
        }
    }

    #[test]
    fn chain_first_record_is_adopted_not_flagged() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        // Mid-stream start (seq 7, not 1) must be adopted silently.
        let rec = ledger_rec(0, 7, 0xdeadbeef, 42, KIND_SWITCH);
        assert!(on_ledger_event(rec, None, &mut chain, &mut reg, 100).is_none());
        assert_eq!(chain.per_cpu[&0].seq, 7);
    }

    #[test]
    fn chain_contiguous_records_produce_no_detections() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(0, 10, &mut chain, &mut reg);
        assert_eq!(chain.per_cpu[&0].seq, 10);
        assert!(chain.last_record > 0);
    }

    #[test]
    fn chain_gap_is_detected_exactly_once_then_resyncs() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(0, 5, &mut chain, &mut reg);

        // Suppressed seq 6; next arrival is 7.
        let cc_head = chain.per_cpu[&0].head;
        let rec = ledger_rec(0, 7, cc_head, 1, KIND_SWITCH);
        let d =
            on_ledger_event(rec, None, &mut chain, &mut reg, 10_000).expect("gap must be detected");
        assert_eq!(d.class, DetectionClass::Tamper);
        assert!(d.details.contains("gap"), "details: {}", d.details);

        // Chain resynced: the next contiguous record (8) is clean.
        let head = chain.per_cpu[&0].head;
        let rec8 = ledger_rec(0, 8, head, 1, KIND_SWITCH);
        assert!(on_ledger_event(rec8, None, &mut chain, &mut reg, 10_001).is_none());
    }

    #[test]
    fn chain_divergence_is_detected() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(0, 3, &mut chain, &mut reg);

        // Contiguous seq but a forged prev_head.
        let rec = ledger_rec(0, 4, 0xaaaabbbbccccdddd, 1, KIND_SWITCH);
        let d = on_ledger_event(rec, None, &mut chain, &mut reg, 5_000)
            .expect("divergence must be detected");
        assert_eq!(d.class, DetectionClass::Tamper);
        assert!(d.details.contains("divergence"), "details: {}", d.details);
    }

    #[test]
    fn chain_cpus_are_independent() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(0, 4, &mut chain, &mut reg);
        build_chain(1, 2, &mut chain, &mut reg);
        // cpu1 continues with ITS OWN head — cpu0's chain must not matter.
        let head1 = chain.per_cpu[&1].head;
        let rec = ledger_rec(1, 3, head1, 1, KIND_SWITCH);
        assert!(on_ledger_event(rec, None, &mut chain, &mut reg, 900).is_none());
        // A foreign prev_head (cpu0's) on cpu1's chain is still a divergence.
        let head0 = chain.per_cpu[&0].head;
        let rec = ledger_rec(1, 4, head0, 1, KIND_SWITCH);
        assert!(on_ledger_event(rec, None, &mut chain, &mut reg, 901).is_some());
    }

    #[test]
    fn heartbeat_advances_chain_without_registry_entry() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(2, 3, &mut chain, &mut reg);
        let head = chain.per_cpu[&2].head;
        let before = reg.len();
        let rec = ledger_rec(2, 4, head, 0, KIND_HEARTBEAT); // tgid == 0
        assert!(on_ledger_event(rec, None, &mut chain, &mut reg, 4_000).is_none());
        assert_eq!(reg.len(), before, "heartbeat must not create a record");
        assert_eq!(chain.per_cpu[&2].seq, 4);
    }

    #[test]
    fn ledger_event_updates_registry_sched_last() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        let rec = ledger_rec(0, 1, 0, 4321, KIND_FORK);
        assert!(on_ledger_event(rec, None, &mut chain, &mut reg, 7_777).is_none());
        let r = reg.get(&4321).expect("fork must seed the registry");
        assert_eq!(r.sched_last, 7_777);
    }

    #[test]
    fn notary_matching_current_position_is_clean() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(0, 5, &mut chain, &mut reg);
        let ev = NotaryEvent {
            cpu: 0,
            _pad: 0,
            seq: chain.per_cpu[&0].seq,
            head: chain.per_cpu[&0].head,
            ktime_ns: 0,
        };
        assert!(on_notary_event(ev, &mut chain, 1).is_none());
    }

    #[test]
    fn notary_at_older_seq_in_history_is_clean() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(0, 5, &mut chain, &mut reg);
        // Reconstruct the head at seq 3 from history.
        let head3 = chain.per_cpu[&0]
            .history
            .iter()
            .find(|(s, _)| *s == 3)
            .unwrap()
            .1;
        let ev = NotaryEvent {
            cpu: 0,
            _pad: 0,
            seq: 3,
            head: head3,
            ktime_ns: 0,
        };
        assert!(on_notary_event(ev, &mut chain, 1).is_none());
    }

    #[test]
    fn notary_head_mismatch_is_detected() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(0, 5, &mut chain, &mut reg);
        let seq = chain.per_cpu[&0].seq;
        let ev = NotaryEvent {
            cpu: 0,
            _pad: 0,
            seq,
            head: 0x1234_5678_9abc_def0,
            ktime_ns: 0,
        };
        let d = on_notary_event(ev, &mut chain, 1).expect("mismatch must be detected");
        assert_eq!(d.class, DetectionClass::Tamper);
        assert!(d.details.contains("edited"), "details: {}", d.details);
    }

    #[test]
    fn notary_ahead_of_chain_is_detected_after_confirmation() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(0, 5, &mut chain, &mut reg);
        // First ahead-notary: tentative only (may be an in-flight race).
        let ev = NotaryEvent {
            cpu: 0,
            _pad: 0,
            seq: chain.per_cpu[&0].seq + 10,
            head: 0,
            ktime_ns: 0,
        };
        assert!(
            on_notary_event(ev, &mut chain, 1).is_none(),
            "first ahead-notary is tentative, not an alert"
        );
        // Chain still behind at the next notary → confirmed suppression.
        let ev2 = NotaryEvent {
            cpu: 0,
            _pad: 0,
            seq: chain.per_cpu[&0].seq + 11,
            head: 0,
            ktime_ns: 0,
        };
        let d = on_notary_event(ev2, &mut chain, 1).expect("confirmed ahead must be detected");
        assert!(d.details.contains("suppressed"), "details: {}", d.details);
    }

    #[test]
    fn notary_benign_in_flight_race_does_not_alert() {
        // Regression for the QEMU round: a notary lands one record ahead of
        // consumption (off-by-one), the records arrive, the next notary is
        // clean — no TAMPER may fire.
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(0, 5, &mut chain, &mut reg);
        let head_at = |chain: &ChainTracker, seq: u64| {
            chain.per_cpu[&0]
                .history
                .iter()
                .find(|(s, _)| *s == seq)
                .unwrap()
                .1
        };
        // Notary races append: seq 6 not yet consumed locally.
        let ev = NotaryEvent {
            cpu: 0,
            _pad: 0,
            seq: 6,
            head: 0xdead_beef,
            ktime_ns: 0,
        };
        assert!(on_notary_event(ev, &mut chain, 1).is_none(), "tentative");
        // The in-flight record arrives (seq 6 verified).
        let rec = ledger_rec(0, 6, head_at(&chain, 5), 1, KIND_SWITCH);
        assert!(on_ledger_event(rec, None, &mut chain, &mut reg, 2).is_none());
        // Next notary at the current position — clean, pending cleared.
        let ev2 = NotaryEvent {
            cpu: 0,
            _pad: 0,
            seq: chain.per_cpu[&0].seq,
            head: chain.per_cpu[&0].head,
            ktime_ns: 0,
        };
        assert!(
            on_notary_event(ev2, &mut chain, 3).is_none(),
            "caught-up race must not alert"
        );
    }

    #[test]
    fn notary_stale_beyond_history_is_ignored() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        build_chain(0, 5, &mut chain, &mut reg);
        // A seq below the local chain that never existed in history is not a
        // provable anomaly (information aged out legitimately).
        let ev = NotaryEvent {
            cpu: 0,
            _pad: 0,
            seq: 0,
            head: 0xbad,
            ktime_ns: 0,
        };
        assert!(on_notary_event(ev, &mut chain, 1).is_none());
    }

    #[test]
    fn notary_unknown_cpu_is_ignored() {
        let mut chain = ChainTracker::default();
        let ev = NotaryEvent {
            cpu: 9,
            _pad: 0,
            seq: 5,
            head: 0,
            ktime_ns: 0,
        };
        assert!(on_notary_event(ev, &mut chain, 1).is_none());
    }

    #[test]
    fn exit_record_updates_sched_last() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        let rec = ledger_rec(1, 1, 0, 555, KIND_EXIT);
        assert!(on_ledger_event(rec, None, &mut chain, &mut reg, 42).is_none());
        assert_eq!(reg.get(&555).unwrap().sched_last, 42);
    }

    /// Regression test for the first VM run: the caller resolves a SWITCH
    /// record's thread ID to a different TGID and passes it via
    /// `resolved_tgid`. The record must stay pristine for the chain hash —
    /// mutating it desynced the userspace chain from the kernel's on every
    /// multi-threaded switch (divergence TAMPER storm).
    #[test]
    fn resolved_tgid_does_not_break_the_chain() {
        let mut chain = ChainTracker::default();
        let mut reg = ProcessRegistry::new();
        // Record 1: thread 999 (tgid field = 999), resolved to TGID 42.
        let r1 = ledger_rec(0, 1, 0, 999, KIND_SWITCH);
        let head1 = chain_hash(0, 1, &r1);
        assert!(on_ledger_event(r1, Some(42), &mut chain, &mut reg, 1_000).is_none());
        assert!(reg.contains_key(&42), "registry must use the resolved TGID");
        // Record 2 chains from the KERNEL's hash of record 1 (tgid 999), not
        // from any user-side mutation. Must verify cleanly.
        let r2 = ledger_rec(0, 2, head1, 777, KIND_SWITCH);
        assert!(
            on_ledger_event(r2, None, &mut chain, &mut reg, 2_000).is_none(),
            "chain must not flag divergence when caller used resolved_tgid"
        );
    }

    // ── on_lkm_event tests ───────────────────────────────────────────────────

    fn lkm_event(tgid: u32, allowed: bool) -> spica_common::LkmEvent {
        spica_common::LkmEvent {
            pid: tgid,
            tgid,
            comm: [0u8; 16],
            ktime_ns: 0,
            allowed: if allowed { 1 } else { 0 },
            _pad: 0,
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

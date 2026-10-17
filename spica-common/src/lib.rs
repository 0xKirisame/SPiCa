#![no_std]

//! Shared wire types for the SPiCa ledger architecture.
//!
//! The eBPF side appends `LedgerRecord`s to a frozen ARRAY map (the kernel
//! evidence ring) and mirrors them to a ring buffer (transport). Each record
//! carries a per-CPU sequence number and the previous per-CPU chain head; the
//! chain head is `chain_hash(prev_head, seq, record)`. The userspace side
//! recomputes the identical hash (same function, same crate — no drift) and
//! verifies continuity. The NMI program emits `NotaryEvent` snapshots of the
//! per-CPU (seq, head) pairs; userspace cross-checks them against its running
//! chain. Any suppression or edit of in-flight records breaks continuity and
//! is detected as TAMPER.

use sha2::{Digest as _, Sha256};

/// Upper bound on CPUs supported by the per-CPU .bss chain state.
/// Slots beyond the online CPU count are never touched.
pub const MAX_CPUS: usize = 128;

/// Slots in the kernel-side evidence ring (frozen ARRAY map).
/// 65536 x 56 bytes = ~3.6 MB, bounded for the lifetime of the host.
pub const LEDGER_SLOTS: u32 = 65_536;

// ── Ledger record kinds ──────────────────────────────────────────────────────

/// sched_switch sighting of a TGID (after per-CPU same-TGID dedupe).
pub const KIND_SWITCH: u32 = 0;
/// sched_process_fork: a new task entered the system.
pub const KIND_FORK: u32 = 1;
/// sched_process_exit: a task left the system.
pub const KIND_EXIT: u32 = 2;
/// Per-CPU liveness record (idle switches / dedupe suppression keeps the
/// per-CPU chain advancing even when no new TGID is scheduled).
pub const KIND_HEARTBEAT: u32 = 3;

/// One append-only ledger entry. 56 bytes, no interior padding.
///
/// `seq` and `prev_head` are per-CPU: each CPU owns an independent chain,
/// which removes all cross-CPU write races without locks (a single CPU has a
/// single writer at a time: sched/fork/exit tracepoints do not nest, and the
/// NMI program never appends — it only snapshots).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LedgerRecord {
    pub pid: u32,
    pub tgid: u32,
    pub cpu: u32,
    pub kind: u32,
    pub comm: [u8; 16],
    pub ktime_ns: u64,
    /// Per-CPU monotonic sequence. First record on a CPU has seq == 1.
    pub seq: u64,
    /// Per-CPU chain head before this record was appended.
    pub prev_head: u64,
}

const _: () = assert!(core::mem::size_of::<LedgerRecord>() == 56);

/// NMI notary snapshot of one CPU's chain position, emitted ~1/sec/CPU.
/// Userspace checks this against its own running chain: a notary pair that is
/// ahead of the userspace chain, or a seq/head mismatch, is proof of tampering.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotaryEvent {
    pub cpu: u32,
    pub _pad: u32,
    pub seq: u64,
    pub head: u64,
    pub ktime_ns: u64,
}

const _: () = assert!(core::mem::size_of::<NotaryEvent>() == 32);

/// Emitted by the BPF LSM hook on every READING_MODULE attempt.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LkmEvent {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
    pub ktime_ns: u64,
    /// 0 = blocked (gate locked), 1 = allowed (boot window)
    pub allowed: u32,
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LedgerRecord {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NotaryEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LkmEvent {}

// ── Chain hash ───────────────────────────────────────────────────────────────

// ── TPM PCR anchor (stage 3) ─────────────────────────────────────────────────

/// Debug-range PCR used as the out-of-band finality anchor. PCR 16 is the
/// first application-free slot: not touched by firmware/bootloaders, reset to
/// zero on every reboot (each boot gets a fresh genesis), and extendable by
/// the daemon with no TPM auth policy by default.
pub const PCR_INDEX: u32 = 16;

/// Domain-separation tag bound into every anchor digest.
pub const ANCHOR_TAG: &[u8; 12] = b"SPiCaANCHOR1";

/// One verified chain position, as snapshotted from `ChainTracker`.
pub type ChainSnapshot = [(u32, u64, u64)]; // (cpu, seq, head), sorted by cpu

/// The value extended into PCR16 each epoch: a SHA-256 commitment to the
/// daemon's *verified* view of all per-CPU chains.
///
/// Layout (all little-endian, hashed field-by-field):
/// `ANCHOR_TAG ‖ epoch:u64 ‖ cpu_count:u32 ‖ (cpu:u32 ‖ seq:u64 ‖ head:u64)*`
///
/// An empty snapshot still commits (cpu_count = 0) — every epoch proves the
/// daemon is alive and looking, even on an idle machine.
pub fn anchor_digest(epoch: u64, snapshot: &ChainSnapshot) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ANCHOR_TAG);
    h.update(epoch.to_le_bytes());
    h.update((snapshot.len() as u32).to_le_bytes());
    for &(cpu, seq, head) in snapshot {
        h.update(cpu.to_le_bytes());
        h.update(seq.to_le_bytes());
        h.update(head.to_le_bytes());
    }
    h.finalize().into()
}

/// Genesis anchor digest: the FIRST value SPiCa extends into PCR16 each
/// boot, derived from the TPM-unsealed secret. Offline verification checks
/// that PCR16's first extend equals this (computed from the install record).
#[inline]
pub fn genesis_digest(secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SPiCaGENESIS");
    h.update(secret);
    h.finalize().into()
}

/// One TPM2_PCR_Extend step for the SHA-256 bank: `new = SHA256(old ‖ value)`.
///
/// The daemon keeps a local mirror of the PCR value by applying this to every
/// anchor it extends; comparing the mirror against a live PCR read each epoch
/// turns attacker garbage-extension (the one TPM operation a rootkit can
/// still perform) into a detectable, alertable divergence.
pub fn pcr_step(mirror: [u8; 32], anchor: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(mirror);
    h.update(anchor);
    h.finalize().into()
}

/// FNV-1a-64 chain step: folds the previous head, the sequence number, and
/// every content field of the record into the new head.
///
/// This is a **tamper-evidence chain, not a MAC** — anyone can recompute it.
/// Security comes from the head living in a frozen `.bss` global (syscall
/// writes get EPERM after `bpf_map_freeze`) that only SPiCa's own programs
/// can advance, cross-notarized by the NMI program. Field bytes are hashed
/// explicitly (not the raw struct) so padding can never affect the result.
///
/// Used by BOTH the eBPF side and the userspace verifier — one implementation,
/// one definition of continuity.
#[inline]
pub fn chain_hash(prev_head: u64, seq: u64, rec: &LedgerRecord) -> u64 {
    fn mix(h: &mut u64, bytes: &[u8]) {
        const FNV_PRIME: u64 = 0x100_0000_01b3;
        for &b in bytes {
            *h ^= b as u64;
            *h = h.wrapping_mul(FNV_PRIME);
        }
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    mix(&mut h, &prev_head.to_ne_bytes());
    mix(&mut h, &seq.to_ne_bytes());
    mix(&mut h, &rec.pid.to_ne_bytes());
    mix(&mut h, &rec.tgid.to_ne_bytes());
    mix(&mut h, &rec.cpu.to_ne_bytes());
    mix(&mut h, &rec.kind.to_ne_bytes());
    mix(&mut h, &rec.comm);
    mix(&mut h, &rec.ktime_ns.to_ne_bytes());
    h
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn sample(seq: u64, prev_head: u64) -> (LedgerRecord, u64) {
        let rec = LedgerRecord {
            pid: 4321,
            tgid: 1234,
            cpu: 3,
            kind: KIND_SWITCH,
            comm: *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
            ktime_ns: 9_876_543_210,
            seq,
            prev_head,
        };
        let head = chain_hash(prev_head, seq, &rec);
        (rec, head)
    }

    #[test]
    fn record_is_56_bytes() {
        assert_eq!(core::mem::size_of::<LedgerRecord>(), 56);
    }

    #[test]
    fn notary_event_is_32_bytes() {
        assert_eq!(core::mem::size_of::<NotaryEvent>(), 32);
    }

    #[test]
    fn chain_hash_is_deterministic() {
        let (rec, h1) = sample(7, 0x1234_5678_9abc_def0);
        let h2 = chain_hash(0x1234_5678_9abc_def0, 7, &rec);
        assert_eq!(h1, h2);
    }

    #[test]
    fn chain_hash_depends_on_prev_head() {
        let (rec, h1) = sample(1, 111);
        let h2 = chain_hash(222, 1, &rec);
        assert_ne!(h1, h2);
    }

    #[test]
    fn chain_hash_depends_on_seq() {
        let (rec, h1) = sample(1, 999);
        let h2 = chain_hash(999, 2, &rec);
        assert_ne!(h1, h2);
    }

    #[test]
    fn chain_hash_depends_on_every_content_field() {
        let (_, base) = sample(5, 77);
        // Mutate each content field one at a time; head must change.
        let mutations: [(&str, fn(&mut LedgerRecord)); 6] = [
            ("pid", |r| r.pid ^= 1),
            ("tgid", |r| r.tgid ^= 1),
            ("cpu", |r| r.cpu ^= 1),
            ("kind", |r| r.kind = KIND_EXIT),
            ("comm", |r| r.comm[0] ^= 1),
            ("ktime", |r| r.ktime_ns ^= 1),
        ];
        for (name, m) in mutations {
            let (mut rec, _) = sample(5, 77);
            m(&mut rec);
            assert_ne!(chain_hash(77, 5, &rec), base, "{name} must affect head");
        }
    }

    #[test]
    fn chain_hash_distinguishes_distinct_content() {
        let (r1, h1) = sample(1, 0);
        let mut r2 = r1;
        r2.pid += 1; // different content, same (prev_head, seq) position
        let h2 = chain_hash(0, 1, &r2);
        assert_ne!(h1, h2);
        // Identical inputs still hash identically (replay is caught by seq
        // monotonicity upstream, not by the hash itself).
        assert_eq!(chain_hash(0, 1, &r1), h1);
    }

    #[test]
    fn chain_linkage_property() {
        // A 3-link chain: heads must all differ and depend on full history.
        let (r1, h1) = sample(1, 0);
        let mut r2 = r1;
        r2.seq = 2;
        r2.prev_head = h1;
        let h2 = chain_hash(h1, 2, &r2);
        let mut r3 = r2;
        r3.seq = 3;
        r3.prev_head = h2;
        let h3 = chain_hash(h2, 3, &r3);
        assert_ne!(h1, 0);
        assert_ne!(h2, h1);
        assert_ne!(h3, h2);
    }

    // ── PCR anchor tests ─────────────────────────────────────────────────────

    use super::{ANCHOR_TAG, anchor_digest, pcr_step};

    #[test]
    fn anchor_digest_is_deterministic_and_tagged() {
        let snap: &[(u32, u64, u64)] = &[(0, 5, 0xaaaa), (1, 9, 0xbbbb)];
        assert_eq!(anchor_digest(1, snap), anchor_digest(1, snap));
        assert_ne!(
            anchor_digest(1, snap),
            anchor_digest(2, snap),
            "epoch matters"
        );
    }

    #[test]
    fn anchor_digest_covers_every_field_and_cpu() {
        let base: &[(u32, u64, u64)] = &[(0, 5, 111), (1, 9, 222)];
        let b = anchor_digest(1, base);
        let m_cpu: &[(u32, u64, u64)] = &[(0, 5, 111), (2, 9, 222)];
        let m_seq: &[(u32, u64, u64)] = &[(0, 6, 111), (1, 9, 222)];
        let m_head: &[(u32, u64, u64)] = &[(0, 5, 111), (1, 9, 223)];
        assert_ne!(anchor_digest(1, m_cpu), b, "cpu id matters");
        assert_ne!(anchor_digest(1, m_seq), b, "seq matters");
        assert_ne!(anchor_digest(1, m_head), b, "head matters");
    }

    #[test]
    fn anchor_digest_empty_snapshot_is_still_a_commitment() {
        let a = anchor_digest(1, &[]);
        let b = anchor_digest(2, &[]);
        assert_ne!(a, b, "epoch advances even with no chains");
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn pcr_step_matches_tpm2_extend_semantics() {
        // TPM2_PCR_Extend (sha256 bank): new = SHA256(old || value).
        // Reference: known-answer construction.
        let old = [0u8; 32]; // PCRs start at zero after reboot
        let val = [0xABu8; 32];
        let stepped = pcr_step(old, val);
        assert_ne!(stepped, old);
        // Manual sha256 of the concatenation must match.
        let mut h = sha2::Sha256::new();
        h.update(old);
        h.update(val);
        let manual: [u8; 32] = h.finalize().into();
        assert_eq!(stepped, manual);
    }

    #[test]
    fn genesis_digest_is_tagged_and_deterministic() {
        let s = [7u8; 32];
        assert_eq!(super::genesis_digest(&s), super::genesis_digest(&s));
        // Tagged: differs from a bare hash of the secret.
        let mut h = sha2::Sha256::new();
        h.update(s);
        let bare: [u8; 32] = h.finalize().into();
        assert_ne!(super::genesis_digest(&s), bare);
    }

    #[test]
    fn anchor_tag_is_stable() {
        // The tag is part of the committed format — changing it changes every
        // digest ever extended. Lock it down.
        assert_eq!(ANCHOR_TAG, b"SPiCaANCHOR1");
    }
}

#![no_std]
#![no_main]
#![allow(static_mut_refs)]

//! SPiCa eBPF object — ledger architecture.
//!
//! Integrity model (replaces the old .bss heartbeat + XOR key design):
//!
//! - Every observation is a `LedgerRecord` appended to a per-CPU hash chain
//!   (`chain_hash` in spica-common). Chain state (`LEDGER_HEAD`/`LEDGER_SEQ`)
//!   lives in `.bss`, which userspace FREEZES via `bpf_map_freeze` right after
//!   load: syscall updates to a frozen map return EPERM, so a rootkit can no
//!   longer spoof state through `BPF_MAP_UPDATE_ELEM`, while programs here
//!   keep write access (freeze only gates the syscall path).
//! - Records are mirrored into a ring buffer for userspace transport. The
//!   userspace verifier recomputes the chain; gaps or divergent heads are
//!   TAMPER.
//! - The NMI perf-event program never appends — it snapshots its CPU's
//!   (seq, head) into `NotaryEvent`s ~1/sec/CPU. Userspace cross-checks the
//!   snapshots against its running chain: a notary pair ahead of the chain,
//!   or a head mismatch at the same seq, is proof of tampering. A total
//!   ledger stall (no seq progress anywhere past the grace window) means the
//!   writer programs are detached/suppressed — detected userspace-side.
//! - Per-CPU chains remove all cross-CPU write races without locks: each CPU
//!   has one writer at a time (sched/fork/exit tracepoints don't nest; NMI
//!   only reads).
//!
//! Secrecy is explicitly NOT the model: the ledger is public-readable. The
//! security claim is append-only-by-construction + tamper-evidence, enforced
//! by freeze + the deny-by-default `bpf()` LSM gate (see spica_lsm_bpfgate).

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_smp_processor_id,
        bpf_ktime_get_ns, bpf_probe_read_kernel_buf,
    },
    macros::{lsm, map, perf_event, tracepoint},
    maps::{Array, RingBuf},
    programs::{LsmContext, PerfEventContext, TracePointContext},
};
use spica_common::{
    KIND_EXIT, KIND_FORK, KIND_HEARTBEAT, KIND_SWITCH, LEDGER_SLOTS, LedgerRecord, LkmEvent,
    MAX_CPUS, NotaryEvent, chain_hash,
};

#[allow(non_upper_case_globals)]
#[unsafe(export_name = "license")]
pub static _license: [u8; 4] = *b"GPL\0";

// ── .bss globals (frozen by userspace via bpf_map_freeze after load) ─────────
//
// SPICA_PID is written by the loader pre-load (override_global). All other
// globals are written only by programs at runtime. After freeze, syscall
// reads still work (the ledger is public) but syscall writes get EPERM.

/// SPiCa's own TGID. Exempts the daemon from the bpf() LSM gate so it can
/// finish loading / freezing. #[used] + export_name + read_volatile prevent
/// LLVM from constant-folding the never-written-in-ebpf global to 0.
#[used]
#[unsafe(export_name = "SPICA_PID")]
static mut SPICA_PID: u32 = 0u32;

/// Per-CPU chain head. Slot [cpu] is written only from that CPU's context.
static mut LEDGER_HEAD: [u64; MAX_CPUS] = [0; MAX_CPUS];

/// Per-CPU sequence number. First append on a CPU yields seq == 1.
static mut LEDGER_SEQ: [u64; MAX_CPUS] = [0; MAX_CPUS];

/// Per-CPU sched dedupe: last TGID scheduled on this CPU. Suppresses a
/// record when the same TGID is scheduled repeatedly (the dominant case).
static mut LAST_TGID: [u32; MAX_CPUS] = [0; MAX_CPUS];

/// Per-CPU heartbeat throttle ktime (see try_sched idle path).
static mut HB_LAST: [u64; MAX_CPUS] = [0; MAX_CPUS];

/// First NMI invocation ktime (grace-period reference, 1/sec throttle).
static mut NMI_FIRST_TICK: u64 = 0;

/// Per-CPU notary emission throttle (each CPU notarizes 1/sec independently;
/// a shared global would throttle CPUs against each other).
static mut NMI_LAST_EMIT: [u64; MAX_CPUS] = [0; MAX_CPUS];

/// Forensic counters: bpf()-gate and LKM-gate denials. The volatile
/// increment inside each deny arm is ALSO a codegen barrier: without a side
/// effect, LLVM fuses `if c {-1} else {0}` into branchless mask+negate
/// (`r0 = -r0`), which the verifier rejects — LSM exit values must be
/// provably in [-4095, 0]. Side effects cannot be speculated into selects,
/// so the branch/phi shape survives every optimization level.
static mut BPF_GATE_DENIES: u32 = 0;
static mut LKM_GATE_DENIES: u32 = 0;

/// One-time uninstall token, written by the loader pre-load (then frozen
/// with the rest of .bss). Knock = any gated bpf() call whose bpf_attr
/// carries these 32 bytes at offset 96 (union padding for every benign
/// command). On match, AUTH_UNTIL opens a 60-second authorization window.
/// Readable via map enumeration only during the pre-gate load window —
/// after the bpf() gate arms, only SPiCa and knock-holders can reach it.
#[used]
#[unsafe(export_name = "AUTH_TOKEN")]
static mut AUTH_TOKEN: [u8; 32] = [0; 32];

/// ktime at which the knock-authorization window expires (0 = closed).
/// Written by the gate program on a valid knock; readable by every gate
/// decision. A window can be re-opened by another knock.
static mut AUTH_UNTIL: u64 = 0;

// ── Named maps ───────────────────────────────────────────────────────────────

/// Kernel-side evidence ring (frozen post-load; program writes allowed).
/// ~3.6 MB, bounded forever. This is the recent-window proof that survives
/// userspace memory tampering; the authoritative full chain lives in the
/// daemon (and, stage 3, TPM PCR anchors).
#[map]
static mut sc_ledger: Array<LedgerRecord> = Array::with_max_entries(LEDGER_SLOTS, 0);

/// Ledger record transport to userspace.
#[map]
static mut sc_sched: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// NMI notary snapshot transport to userspace.
#[map]
static mut sc_nmi: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// LSM module-load gate: 0 = allow (init window), 1 = block all new LKMs.
/// Frozen immediately after userspace closes it.
#[map]
static sc_gate: Array<u32> = Array::with_max_entries(1, 0);

/// Forensic kill flag. Pinned to BPF-FS; survives SIGKILL. Frozen post-load
/// (program writes still work; syscall writes blocked).
#[map]
static mut sc_wd: Array<u32> = Array::with_max_entries(1, 0);

/// LKM load audit log.
#[map]
static mut sc_lsm: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// ── Volatile .bss access helpers ─────────────────────────────────────────────
//
// Cross-function shared state: always volatile, mirroring the constant-fold
// fix from the BTF-bug incident. Reads and writes go through addr_of_mut!
// to avoid references to statics escaping.

#[inline]
unsafe fn rd_u64(p: *const u64) -> u64 {
    unsafe { core::ptr::read_volatile(p) }
}

#[inline]
unsafe fn wr_u64(p: *mut u64, v: u64) {
    unsafe { core::ptr::write_volatile(p, v) }
}

#[inline]
unsafe fn rd_u32(p: *const u32) -> u32 {
    unsafe { core::ptr::read_volatile(p) }
}

#[inline]
unsafe fn wr_u32(p: *mut u32, v: u32) {
    unsafe { core::ptr::write_volatile(p, v) }
}

// ── Ledger append (the single writer path per CPU) ──────────────────────────

/// Bundle for `append_ledger` — passed by reference. (Passing the 16-byte
/// `comm` array by value makes LLVM's BPF backend marshal stack args through
/// R11, which does not exist on eBPF — the verifier rejects with
/// "R11 is invalid". Reference-passing keeps the whole call in R1.)
struct Append {
    kind: u32,
    pid: u32,
    tgid: u32,
    cpu: u32,
    now: u64,
    comm: [u8; 16],
}

/// Append a record to the per-CPU chain, mirror it to the evidence ring and
/// the transport ring buffer. Order matters for NMI skew tolerance: the
/// record (and its evidence slot) become visible BEFORE seq/head advance, so
/// a notary snapshot racing an append sees either the old pair or the new
/// pair — never a half-written record.
#[inline]
unsafe fn append_ledger(a: &Append) {
    unsafe {
        if a.cpu as usize >= MAX_CPUS {
            return;
        }
        let seq_ptr = core::ptr::addr_of_mut!(LEDGER_SEQ[a.cpu as usize]);
        let head_ptr = core::ptr::addr_of_mut!(LEDGER_HEAD[a.cpu as usize]);

        let seq = rd_u64(seq_ptr).wrapping_add(1);
        let prev_head = rd_u64(head_ptr);

        let rec = LedgerRecord {
            pid: a.pid,
            tgid: a.tgid,
            cpu: a.cpu,
            kind: a.kind,
            comm: a.comm,
            ktime_ns: a.now,
            seq,
            prev_head,
        };
        let new_head = chain_hash(prev_head, seq, &rec);

        // Evidence ring: slot = seq % LEDGER_SLOTS (recent window; the full
        // authoritative chain is userspace-side).
        let slot = (seq % LEDGER_SLOTS as u64) as u32;
        if let Some(dst) = sc_ledger.get_ptr_mut(slot) {
            core::ptr::write_volatile(dst, rec);
        }

        // Transport mirror.
        if let Some(mut entry) = sc_sched.reserve::<LedgerRecord>(0) {
            entry.write(rec);
            entry.submit(0);
        }

        // Advance the chain only after the record is durable.
        wr_u64(seq_ptr, seq);
        wr_u64(head_ptr, new_head);
    }
}

// ── Program 1: sched_switch tracepoint (ledger writer + dedupe) ─────────────
//
// Traditional tracepoint format (non-BTF):
//   u8 _unused, u16 _unused, u8 _unused, u8 _unused,
//   char prev_comm[16], pid_t prev_pid, int prev_prio, long prev_state,
//   char next_comm[16], pid_t next_pid, int next_prio
// next_comm @ 40, next_pid @ 56.

#[tracepoint(name = "sched_switch", category = "sched")]
pub fn spica_sched(ctx: TracePointContext) -> u32 {
    match try_sched(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched(ctx: TracePointContext) -> Result<u32, i64> {
    let next_pid: u32 = unsafe { ctx.read_at::<u32>(56)? };
    let cpu_id = unsafe { bpf_get_smp_processor_id() } as u32;
    if cpu_id as usize >= MAX_CPUS {
        return Ok(0);
    }
    let now = unsafe { bpf_ktime_get_ns() };

    if next_pid == 0 {
        // Idle switch: no sighting, but keep the per-CPU chain alive so a
        // busy-hogging or idle CPU can't look like a detached probe. At most
        // one heartbeat record per CPU per second.
        let hb_ptr = unsafe { core::ptr::addr_of_mut!(HB_LAST[cpu_id as usize]) };
        let last = unsafe { rd_u64(hb_ptr) };
        if last == 0 || now.wrapping_sub(last) > 1_000_000_000 {
            unsafe {
                wr_u64(hb_ptr, now);
                append_ledger(&Append {
                    kind: KIND_HEARTBEAT,
                    pid: 0,
                    tgid: 0,
                    cpu: cpu_id,
                    now,
                    comm: [0u8; 16],
                });
            }
        }
        return Ok(0);
    }

    // Same-TGID dedupe: the dominant scheduling pattern (thread rescheduling
    // itself) emits nothing. A record flows on every TGID change.
    let last_ptr = unsafe { core::ptr::addr_of_mut!(LAST_TGID[cpu_id as usize]) };
    if unsafe { rd_u32(last_ptr) } == next_pid {
        return Ok(0);
    }
    unsafe { wr_u32(last_ptr, next_pid) };

    let comm: [u8; 16] = unsafe { ctx.read_at::<[u8; 16]>(40)? };
    unsafe {
        append_ledger(&Append {
            kind: KIND_SWITCH,
            pid: next_pid,
            tgid: next_pid,
            cpu: cpu_id,
            now,
            comm,
        });
    }

    Ok(0)
}

// ── Program 2: sched_process_fork tracepoint (lifecycle writer) ─────────────
//
// Tracepoint format: char parent_comm[16] @8, pid_t parent_pid @24,
// char child_comm[16] @28, pid_t child_pid @44.

#[tracepoint(name = "sched_process_fork", category = "sched")]
pub fn spica_fork(ctx: TracePointContext) -> u32 {
    match try_fork(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_fork(ctx: TracePointContext) -> Result<u32, i64> {
    let child_pid: u32 = unsafe { ctx.read_at::<u32>(44)? };
    if child_pid == 0 {
        return Ok(0);
    }
    let comm: [u8; 16] = unsafe { ctx.read_at::<[u8; 16]>(28)? };
    let cpu_id = unsafe { bpf_get_smp_processor_id() } as u32;
    if cpu_id as usize >= MAX_CPUS {
        return Ok(0);
    }
    unsafe {
        append_ledger(&Append {
            kind: KIND_FORK,
            pid: child_pid,
            tgid: child_pid,
            cpu: cpu_id,
            now: bpf_ktime_get_ns(),
            comm,
        })
    };
    Ok(0)
}

// ── Program 3: sched_process_exit tracepoint (lifecycle writer) ─────────────
//
// Tracepoint format: char comm[16] @8, pid_t pid @24, int prio @28.

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn spica_exit(ctx: TracePointContext) -> u32 {
    match try_exit(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let pid: u32 = unsafe { ctx.read_at::<u32>(24)? };
    if pid == 0 {
        return Ok(0);
    }
    let comm: [u8; 16] = unsafe { ctx.read_at::<[u8; 16]>(8)? };
    let cpu_id = unsafe { bpf_get_smp_processor_id() } as u32;
    if cpu_id as usize >= MAX_CPUS {
        return Ok(0);
    }
    unsafe {
        append_ledger(&Append {
            kind: KIND_EXIT,
            pid,
            tgid: pid,
            cpu: cpu_id,
            now: bpf_ktime_get_ns(),
            comm,
        })
    };
    Ok(0)
}

// ── Program 4: hardware NMI ledger notary ────────────────────────────────────
//
// Fired by the hardware PMU, in NMI context — outside the tracepoint
// dispatch path, not interceptable by kprobes, not hookable via
// bpf_override_return. Never appends to the ledger (a single writer per CPU
// is what makes the chain race-free). Snapshots its own CPU's (seq, head)
// once per second; userspace cross-checks every snapshot against the chain
// it reconstructed from the transport ring:
//   - snapshot.seq ahead of the userspace chain  → records were suppressed
//   - same seq but different head                → records were edited
//   - no seq progress on any CPU past grace      → probes detached/suppressed
//
// Reads use volatile (.bss shared with the writers). A snapshot may race an
// in-flight append and observe the pair one entry behind; userspace history
// matching tolerates bounded lag.

#[perf_event]
pub fn spica_nmi(ctx: PerfEventContext) -> u32 {
    match try_nmi(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_nmi(_ctx: PerfEventContext) -> Result<u32, i64> {
    let cpu_id = unsafe { bpf_get_smp_processor_id() } as u32;
    if cpu_id as usize >= MAX_CPUS {
        return Ok(0);
    }
    let now = unsafe { bpf_ktime_get_ns() };

    // Grace-period reference on first invocation anywhere.
    if unsafe { rd_u64(core::ptr::addr_of_mut!(NMI_FIRST_TICK)) } == 0 {
        unsafe { wr_u64(core::ptr::addr_of_mut!(NMI_FIRST_TICK), now) };
    }

    // Per-CPU throttle: each CPU notarizes independently once per second.
    let emit_ptr = unsafe { core::ptr::addr_of_mut!(NMI_LAST_EMIT[cpu_id as usize]) };
    let last_emit = unsafe { rd_u64(emit_ptr) };
    if last_emit != 0 && now.wrapping_sub(last_emit) < 1_000_000_000 {
        return Ok(0);
    }
    unsafe { wr_u64(emit_ptr, now) };

    let seq = unsafe { rd_u64(core::ptr::addr_of_mut!(LEDGER_SEQ[cpu_id as usize])) };
    let head = unsafe { rd_u64(core::ptr::addr_of_mut!(LEDGER_HEAD[cpu_id as usize])) };

    let ev = NotaryEvent {
        cpu: cpu_id,
        _pad: 0,
        seq,
        head,
        ktime_ns: now,
    };
    if let Some(mut entry) = unsafe { sc_nmi.reserve::<NotaryEvent>(0) } {
        entry.write(ev);
        entry.submit(0);
    }

    Ok(0)
}

// ── Program 5: BPF LSM — block kernel module loading after init window ───────

#[lsm(hook = "kernel_read_file")]
pub fn spica_lsm_modblock(ctx: LsmContext) -> i32 {
    match try_lsm_modblock(ctx) {
        Ok(r) => r,
        Err(_) => 0,
    }
}

fn try_lsm_modblock(ctx: LsmContext) -> Result<i32, i64> {
    let file_id: u32 = unsafe { ctx.arg(1) };
    if file_id != 2 {
        return Ok(0);
    }

    let gate_val = unsafe { sc_gate.get(0).copied().unwrap_or(0) };
    let allowed: u32 = if gate_val == 1 { 0 } else { 1 };

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid & 0xFFFF_FFFF) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let comm = match unsafe { bpf_get_current_comm() } {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };

    let event = LkmEvent {
        pid,
        tgid,
        comm,
        ktime_ns: unsafe { bpf_ktime_get_ns() },
        allowed,
        _pad: 0,
    };
    if let Some(mut entry) = unsafe { sc_lsm.reserve::<LkmEvent>(0) } {
        entry.write(event);
        entry.submit(0);
    }

    if gate_val == 1 {
        // Side effect: count the denial (also blocks select-fusion — see
        // LKM_GATE_DENIES above).
        unsafe {
            let p = core::ptr::addr_of_mut!(LKM_GATE_DENIES);
            wr_u32(p, rd_u32(p).wrapping_add(1));
        }
        Ok(-1)
    } else {
        Ok(0)
    }
}

// ── Program 6: BPF LSM — deny-by-default bpf() syscall gate ─────────────────
//
// Blocks every bpf() syscall from processes whose TGID is not SPICA_PID:
// no BPF_PROG_LOAD (no attacker programs to read/write maps or override
// helpers), no *_GET_FD_BY_ID (no fd acquisition to update/freeze/detach
// SPiCa's objects), no LINK_DETACH. Attached LAST, after all of SPiCa's own
// loads/attaches/pins/freezes complete. Deny-wins LSM stacking: a rootkit
// loading its own permissive LSM program cannot override this verdict — to
// bypass, it must detach this program's link, which itself requires a bpf()
// syscall from a non-SPiCa process... which this gate denies.
//
// SPICA_PID == 0 means the gate never armed (fail-open by construction: the
// global is written pre-load and frozen, so it cannot be zeroed at runtime).

#[lsm(hook = "bpf")]
pub fn spica_lsm_bpfgate(ctx: LsmContext) -> i32 {
    match try_bpfgate(ctx) {
        Ok(r) => r,
        Err(_) => 0,
    }
}

/// Knock offset within bpf_attr: every benign command leaves the union
/// padding at bytes 96..128 untouched, so a knock carrying the token there
/// is unambiguous and harmless.
const KNOCK_ATTR_OFFSET: usize = 96;
/// Knock-authorization window (nanoseconds).
const AUTH_WINDOW_NANOS: u64 = 60_000_000_000;

fn try_bpfgate(ctx: LsmContext) -> Result<i32, i64> {
    let tgid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;
    let spica_tgid = unsafe { rd_u32(core::ptr::addr_of_mut!(SPICA_PID)) };
    let now = unsafe { bpf_ktime_get_ns() };

    // Knock: security_bpf(int cmd, union bpf_attr *attr, unsigned size) —
    // arg(1) is the attr pointer. NOTE: the kernel calls the hook with its
    // OWN copy of bpf_attr (syscall.c copies from user first), so this is a
    // KERNEL pointer — read with the kernel probe, not the user probe.
    // A gated call whose attr padding
    // (offset 96, 32 bytes) equals AUTH_TOKEN opens the authorization
    // window for 60 s.
    //
    // VERIFIER CONSTRAINT: the comparison must be loop-free and use
    // CONSTANT offsets. A `for i in 0..32` over volatile variable-indexed
    // .bss reads makes the verifier's state space explode (observed: 19 s
    // of kernel time in BPF_PROG_LOAD). Constant-offset reads are direct
    // map-value loads — trivial to verify.
    let uattr: u64 = unsafe { ctx.arg(1) };
    if uattr != 0 {
        let mut knock = [0u8; 32];
        if unsafe {
            bpf_probe_read_kernel_buf((uattr as *const u8).add(KNOCK_ATTR_OFFSET), &mut knock)
        }
        .is_ok()
        {
            macro_rules! tok {
                ($i:literal) => {
                    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(AUTH_TOKEN[$i])) }
                };
            }
            let matches = tok!(0) == knock[0]
                && tok!(1) == knock[1]
                && tok!(2) == knock[2]
                && tok!(3) == knock[3]
                && tok!(4) == knock[4]
                && tok!(5) == knock[5]
                && tok!(6) == knock[6]
                && tok!(7) == knock[7]
                && tok!(8) == knock[8]
                && tok!(9) == knock[9]
                && tok!(10) == knock[10]
                && tok!(11) == knock[11]
                && tok!(12) == knock[12]
                && tok!(13) == knock[13]
                && tok!(14) == knock[14]
                && tok!(15) == knock[15]
                && tok!(16) == knock[16]
                && tok!(17) == knock[17]
                && tok!(18) == knock[18]
                && tok!(19) == knock[19]
                && tok!(20) == knock[20]
                && tok!(21) == knock[21]
                && tok!(22) == knock[22]
                && tok!(23) == knock[23]
                && tok!(24) == knock[24]
                && tok!(25) == knock[25]
                && tok!(26) == knock[26]
                && tok!(27) == knock[27]
                && tok!(28) == knock[28]
                && tok!(29) == knock[29]
                && tok!(30) == knock[30]
                && tok!(31) == knock[31];
            // All-zero token means "not provisioned" — never authorize.
            let provisioned = tok!(0) | tok!(1) | tok!(2) | tok!(3) | tok!(4) | tok!(5)
                | tok!(6)
                | tok!(7)
                | tok!(8)
                | tok!(9)
                | tok!(10)
                | tok!(11)
                | tok!(12)
                | tok!(13)
                | tok!(14)
                | tok!(15)
                | tok!(16)
                | tok!(17)
                | tok!(18)
                | tok!(19)
                | tok!(20)
                | tok!(21)
                | tok!(22)
                | tok!(23)
                | tok!(24)
                | tok!(25)
                | tok!(26)
                | tok!(27)
                | tok!(28)
                | tok!(29)
                | tok!(30)
                | tok!(31)
                != 0;
            if matches && provisioned {
                unsafe {
                    wr_u64(core::ptr::addr_of_mut!(AUTH_UNTIL), now + AUTH_WINDOW_NANOS)
                };
            }
        }
    }

    let authorized = now < unsafe { rd_u64(core::ptr::addr_of_mut!(AUTH_UNTIL)) };
    if !authorized && spica_tgid != 0 && tgid != spica_tgid {
        // Side effect: count the denial (also blocks select-fusion — see
        // BPF_GATE_DENIES above).
        unsafe {
            let p = core::ptr::addr_of_mut!(BPF_GATE_DENIES);
            wr_u32(p, rd_u32(p).wrapping_add(1));
        }
        Ok(-1) // -EPERM
    } else {
        Ok(0)
    }
}

// ── Program 7: sched_process_exit watchdog ───────────────────────────────────

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn spica_watchdog(ctx: TracePointContext) -> u32 {
    match try_watchdog(ctx) {
        Ok(r) => r,
        Err(r) => r as u32,
    }
}

fn try_watchdog(_ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid_tgid >> 32) as u32;
    let spica_tgid = unsafe { rd_u32(core::ptr::addr_of_mut!(SPICA_PID)) };
    if spica_tgid != 0 && tgid == spica_tgid {
        if let Some(flag) = unsafe { sc_wd.get_ptr_mut(0) } {
            unsafe { *flag = 1 };
        }
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

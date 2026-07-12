#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    macros::{lsm, map, perf_event, tracepoint},
    maps::{Array, RingBuf},
    programs::{LsmContext, PerfEventContext, TracePointContext},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_smp_processor_id,
        bpf_ktime_get_ns,
    },
};
use spica_common::{LkmEvent, ProcessInfo};

#[allow(non_upper_case_globals)]
#[unsafe(export_name = "license")]
pub static _license: [u8; 4] = *b"GPL\0";

// ── .bss globals ─────────────────────────────────────────────────────────────
//
// All programs in this ELF object share one .bss section. Communication
// between sched_switch and NMI happens through these globals — no maps, no
// ring buffers, no enumerable interfaces.
//
// Written by userspace via set_global() before programs are loaded into the
// kernel (BASE_KEY, SPICA_PID). Written/read by eBPF programs at runtime
// (SCHED_HEARTBEAT, NMI_* globals).

/// XOR obfuscation key. TPM-sourced at runtime; compile-time fallback for VMs.
/// Written by userspace via override_global before load. Reads MUST be
/// volatile — without volatile, LLVM constant-folds to 0 (initial value)
/// because it sees no writes in the eBPF code. export_name forces an
/// unmangled symbol so aya's override_global can find it by name.
#[used]
#[unsafe(export_name = "BASE_KEY")]
static mut BASE_KEY: u64 = 0u64;

/// SPiCa's own TGID, written before load so the watchdog program needs no map.
#[used]
#[unsafe(export_name = "SPICA_PID")]
static mut SPICA_PID: u32 = 0u32;

/// sched_switch heartbeat. Written by the sched program on every invocation
/// with bpf_ktime_get_ns(). Read by the NMI program to verify sched_switch is
/// actually executing. If this value stops changing, sched_switch has been
/// detached, suppressed, or failed to attach (BTF bug, verifier quirk, etc.).
static mut SCHED_HEARTBEAT: u64 = 0u64;

/// NMI's record of the last sched heartbeat it observed. Compared against
/// SCHED_HEARTBEAT on each NMI emission. If equal (and past grace period),
/// sched_switch has stopped running → emit TAMPER.
static mut NMI_LAST_HB: u64 = 0u64;

/// First NMI invocation ktime. Used as the reference for the 5-second grace
/// period — TAMPER is not emitted until grace expires, giving sched_switch
/// time to start producing events after load.
static mut NMI_FIRST_TICK: u64 = 0u64;

/// Throttle: last event emission ktime. NMI emits at most once per second to
/// minimize ring-buffer traffic. Non-emission invocations are a single .bss
/// read + compare + early return — negligible overhead.
static mut NMI_LAST_EMIT: u64 = 0u64;

// ── Named maps ───────────────────────────────────────────────────────────────
//
// Ring buffers, a post-load-writable gate, and a pinnable watchdog flag.
// sc_canary has been removed — .bss heartbeat replaces the canary mechanism
// entirely (.bss writes cannot be intercepted via bpf_map_update_elem hooks).

/// Sched-switch event stream to userspace.
#[map]
static mut sc_sched: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// NMI heartbeat / tamper event stream to userspace.
#[map]
static mut sc_nmi: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// LSM module-load gate: 0 = allow (init window), 1 = block all new LKMs.
#[map]
static sc_gate: Array<u32> = Array::with_max_entries(1, 0);

/// Forensic kill flag. Pinned to BPF-FS; survives SIGKILL.
#[map]
static mut sc_wd: Array<u32> = Array::with_max_entries(1, 0);

/// LKM load audit log.
#[map]
static mut sc_lsm: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// ── Program 1: sched_switch tracepoint ───────────────────────────────────────
//
// Traditional tracepoint format (non-BTF):
// Args: u8 _unused, u16 _unused, u8 _unused, u8 _unused,
//       char prev_comm[16], pid_t prev_pid, int prev_prio, long prev_state,
//       char next_comm[16], pid_t next_pid, int next_prio
// We read next_pid and next_comm directly from the tracepoint arguments.
// NOTE: Cannot access task_struct directly - start_time_ns must come from /proc

#[tracepoint(name = "sched_switch", category = "sched")]
pub fn spica_sched(ctx: TracePointContext) -> u32 {
    match try_sched(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched(ctx: TracePointContext) -> Result<u32, i64> {
    let next_pid: u32 = unsafe { ctx.read_at::<u32>(56)? };
    if next_pid == 0 {
        return Ok(0); // idle task
    }

    let comm: [u8; 16] = unsafe { ctx.read_at::<[u8; 16]>(40)? };
    let pid = next_pid;
    let tgid = next_pid;
    let start_time_ns: u64 = 0;

    let cpu_id = unsafe { bpf_get_smp_processor_id() } as u32;
    let now = unsafe { bpf_ktime_get_ns() };
    let key = unsafe { core::ptr::read_volatile(core::ptr::addr_of_mut!(BASE_KEY)) };

    // Update heartbeat for NMI integrity check. This is the critical write —
    // if sched_switch stops executing (detached, suppressed, BTF failure),
    // SCHED_HEARTBEAT stops changing and the NMI program detects it.
    unsafe { SCHED_HEARTBEAT = now };

    let mut info = ProcessInfo {
        pid,
        tgid,
        comm,
        last_seen: now,
        start_time_ns,
        cpu: cpu_id,
        event_type: 0,
    };
    spica_common::xor_fields(&mut info, key);

    if let Some(mut entry) = unsafe { sc_sched.reserve::<ProcessInfo>(0) } {
        entry.write(info);
        entry.submit(0);
    }

    Ok(0)
}

// ── Program 2: Hardware NMI integrity checker ────────────────────────────────
//
// Fired by the hardware PMU. Runs in NMI context — outside the tracepoint
// dispatch path, not interceptable by kprobes (structurally unreliable in NMI
// context), not hookable via bpf_override_return (NMI handler is void).
//
// The integrity check is a .bss heartbeat comparison:
//   - sched_switch writes SCHED_HEARTBEAT on every invocation
//   - NMI reads SCHED_HEARTBEAT and compares to NMI_LAST_HB
//   - If unchanged past the 5-second grace period → sched_switch stopped
//     running → emit event_type=1 (TAMPER)
//   - If changed → sched_switch is alive → emit event_type=0 (heartbeat)
//
// Immunity properties:
//   - Reads .bss directly (memory load, not a function call) — cannot be
//     intercepted by bpf_override_return which hijacks function *calls*
//   - Runs from hardware interrupt — not in the tracepoint dispatch chain
//   - Uses no BPF helpers that could be fmod_ret-hooked on the critical path
//   - Emits at most once per second (throttled) — near-zero ring-buffer traffic

#[perf_event]
pub fn spica_nmi(ctx: PerfEventContext) -> u32 {
    match try_nmi(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_nmi(_ctx: PerfEventContext) -> Result<u32, i64> {
    let now = unsafe { bpf_ktime_get_ns() };

    // Initialize grace period reference on first invocation.
    if unsafe { NMI_FIRST_TICK } == 0 {
        unsafe { NMI_FIRST_TICK = now; }
    }

    // Throttle: emit at most once per second. Non-emission invocations do
    // minimal work (read ktime, read NMI_LAST_EMIT, compare, return).
    let last_emit = unsafe { NMI_LAST_EMIT };
    if last_emit != 0 && now.wrapping_sub(last_emit) < 1_000_000_000 {
        return Ok(0);
    }

    // Read sched heartbeat and compare to last observed value.
    let sched_hb = unsafe { SCHED_HEARTBEAT };
    let grace_expired = now.wrapping_sub(unsafe { NMI_FIRST_TICK }) > 5_000_000_000;

    // TAMPER if: past grace period AND heartbeat unchanged since last check.
    // Both "sched never fired" (sched_hb == 0 == NMI_LAST_HB) and
    // "sched stopped firing" (sched_hb == NMI_LAST_HB, both nonzero) are
    // covered by the single equality check.
    let tamper = grace_expired && sched_hb == unsafe { NMI_LAST_HB };

    // Update state.
    unsafe { NMI_LAST_HB = sched_hb; }
    unsafe { NMI_LAST_EMIT = now; }

    // Emit event.
    let cpu_id = unsafe { bpf_get_smp_processor_id() } as u32;
    let key = unsafe { core::ptr::read_volatile(core::ptr::addr_of_mut!(BASE_KEY)) };

    let mut info = ProcessInfo {
        pid: 0,
        tgid: 0,
        comm: [0u8; 16],
        last_seen: now,
        start_time_ns: 0,
        cpu: cpu_id,
        event_type: if tamper { 1 } else { 0 },
    };
    spica_common::xor_fields(&mut info, key);

    if let Some(mut entry) = unsafe { sc_nmi.reserve::<ProcessInfo>(0) } {
        entry.write(info);
        entry.submit(0);
    }

    Ok(0)
}

// ── Program 3: BPF LSM — block kernel module loading after init window ────────

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
    let pid  = (pid_tgid & 0xFFFF_FFFF) as u32;
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

    if gate_val == 1 { Ok(-1) } else { Ok(0) }
}

// ── Program 4: sched_process_exit watchdog ────────────────────────────────────

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
    let spica_tgid = unsafe { core::ptr::read_volatile(core::ptr::addr_of_mut!(SPICA_PID)) };
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

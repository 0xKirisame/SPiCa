//! eBPF runtime lifecycle: load programs, attach, manage ring buffers, pin watchdog.
//!
//! Encapsulates the ~95 lines of inline setup that used to live in main.rs.
//! main.rs holds the tokio::select! loop and calls into BpfRuntime via
//! the sched_rb_mut / nmi_rb_mut / lsm_rb_mut accessors.
//!
//! See docs/superpowers/specs/2026-06-20-spica-v4-refactor-design.md §10.

use anyhow::Result;
use aya::{
    include_bytes_aligned,
    maps::{Array, RingBuf},
    programs::{BtfTracePoint, Lsm, PerfEvent, TracePoint, perf_event},
    util, Bpf, Btf,
};
use std::fs;
use tokio::io::unix::AsyncFd;

pub const WATCHDOG_PIN: &str = "/sys/fs/bpf/spica_watchdog";

pub struct BpfRuntime {
    #[allow(dead_code)]  // owns the loaded programs; kept alive for detach-on-drop
    bpf: Bpf,
    sched_rb: AsyncFd<RingBuf>,
    nmi_rb: AsyncFd<RingBuf>,
    lsm_rb: AsyncFd<RingBuf>,
    lsm_attached: bool,
}

impl BpfRuntime {
    /// Load eBPF, set globals, attach programs, pin watchdog, take ring buffers.
    ///
    /// Returns the runtime + whether the LSM gate attached (kernel config
    /// dependent). Caller locks the gate immediately after attach via
    /// `lock_lsm_gate()` if `lsm_attached` is true.
    pub fn load(
        base_key: u64,
        spica_pid: u32,
        integrity_token: u64,
    ) -> Result<(Self, bool)> {
        let mut bpf = Bpf::load(include_bytes_aligned!(
            concat!(env!("OUT_DIR"), "/spica")
        ))?;

        // .bss globals — written before any program is loaded into the kernel.
        // set_global modifies the backing ELF section; the kernel receives
        // these as part of program load, not via an enumerable map update.
        bpf.set_global("BASE_KEY", base_key, false)?;
        bpf.set_global("SPICA_PID", spica_pid, false)?;
        bpf.set_global("INTEGRITY_TOKEN", integrity_token, false)?;

        let btf = Btf::from_sys_fs()?;

        // 1. sched_switch tracepoint — always available
        let sched_prog: &mut BtfTracePoint =
            bpf.program_mut("spica_sched").unwrap().try_into()?;
        sched_prog.load("sched_switch", &btf)?;
        sched_prog.attach()?;

        // 2. LSM gate — kernel config dependent (CONFIG_BPF_LSM + lsm=bpf)
        let lsm_attached = fs::read_to_string("/sys/kernel/security/lsm")
            .map(|s| s.contains("bpf"))
            .unwrap_or(false);
        if lsm_attached {
            let lsm_prog: &mut Lsm =
                bpf.program_mut("spica_lsm_modblock").unwrap().try_into()?;
            lsm_prog.load("kernel_read_file", &btf)?;
            lsm_prog.attach()?;
        }

        // 3. Watchdog tracepoint — always available
        let watchdog_prog: &mut TracePoint =
            bpf.program_mut("spica_watchdog").unwrap().try_into()?;
        watchdog_prog.load()?;
        watchdog_prog.attach("sched", "sched_process_exit")?;

        // 4. Write canary BEFORE NMI attaches to avoid spurious TAMPER on startup.
        //    sc_canary exists as soon as Bpf::load() runs (maps are created then).
        //    If we wrote it after nmi_prog.attach(), the NMI could fire in the
        //    gap and see canary=0 vs INTEGRITY_TOKEN!=0 → false TAMPER.
        {
            let mut canary_map: Array<_, u64> =
                bpf.map_mut("sc_canary").unwrap().try_into()?;
            canary_map.set(0, integrity_token, 0)?;
        }

        // 5. NMI perf event on all online CPUs (~100-300Hz depending on CPU speed)
        let nmi_prog: &mut PerfEvent =
            bpf.program_mut("spica_nmi").unwrap().try_into()?;
        nmi_prog.load()?;
        for cpu in util::online_cpus()? {
            nmi_prog.attach(
                perf_event::PerfTypeId::Hardware,
                perf_event::perf_hw_id::HW_CPU_CYCLES as u64,
                perf_event::SamplePolicy::Period(10_000_000),
                cpu,
                None,
            )?;
        }

        // 6. Pin watchdog map to BPF-FS so it outlives a SIGKILL.
        bpf.map("sc_wd").unwrap().pin(WATCHDOG_PIN)?;

        // 7. Take ring buffers into AsyncFd. take_map moves them out of `bpf`
        //    into our ownership; the programs themselves stay attached via
        //    the links held inside `bpf`.
        let sched_rb = AsyncFd::new(RingBuf::try_from(bpf.take_map("sc_sched").unwrap())?)?;
        let nmi_rb = AsyncFd::new(RingBuf::try_from(bpf.take_map("sc_nmi").unwrap())?)?;
        let lsm_rb = AsyncFd::new(RingBuf::try_from(bpf.take_map("sc_lsm").unwrap())?)?;

        Ok((
            Self { bpf, sched_rb, nmi_rb, lsm_rb, lsm_attached },
            lsm_attached,
        ))
    }

    /// Set sc_gate[0] = 1, blocking all subsequent LKM loads with EPERM.
    /// No-op (returns Ok(())) if the LSM program didn't attach.
    pub fn lock_lsm_gate(&mut self) -> Result<()> {
        if !self.lsm_attached {
            return Ok(());
        }
        let mut gate: Array<_, u32> = self.bpf.map_mut("sc_gate").unwrap().try_into()?;
        gate.set(0, 1u32, 0)?;
        Ok(())
    }

    pub fn lsm_attached(&self) -> bool { self.lsm_attached }

    pub fn sched_rb_mut(&mut self) -> &mut AsyncFd<RingBuf> { &mut self.sched_rb }
    pub fn nmi_rb_mut(&mut self) -> &mut AsyncFd<RingBuf> { &mut self.nmi_rb }
    pub fn lsm_rb_mut(&mut self) -> &mut AsyncFd<RingBuf> { &mut self.lsm_rb }
}

// ── Watchdog pin helpers ─────────────────────────────────────────────────────

/// Returns true if a previous SPiCa instance left a watchdog pin behind
/// (meaning it was killed ungracefully — SIGKILL, OOM, crash).
pub fn watchdog_pin_exists() -> bool {
    std::path::Path::new(WATCHDOG_PIN).exists()
}

/// Remove the watchdog pin. Called on clean shutdown (SIGTERM/SIGINT) and
/// on startup after detecting a leftover pin from a previous run.
pub fn clear_watchdog_pin() {
    let _ = fs::remove_file(WATCHDOG_PIN);
}

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
    maps::{MapData, RingBuf},
    programs::{BtfTracePoint, Lsm, PerfEvent, TracePoint, perf_event},
    util, Ebpf, EbpfLoader, Btf,
};
use std::fs;
use tokio::io::unix::AsyncFd;

/// Type alias for Array<u32> maps
type ArrayU32 = aya::maps::Array<MapData, u32>;
/// Type alias for Array<u64> maps
type ArrayU64 = aya::maps::Array<MapData, u64>;

pub const WATCHDOG_PIN: &str = "/sys/fs/bpf/spica_watchdog";

pub struct BpfRuntime {
    #[allow(dead_code)]  // owns the loaded programs; kept alive for detach-on-drop
    bpf: Ebpf,
    sched_rb: AsyncFd<RingBuf<MapData>>,
    nmi_rb: AsyncFd<RingBuf<MapData>>,
    lsm_rb: AsyncFd<RingBuf<MapData>>,
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
        let mut loader = EbpfLoader::new();

        // Set .bss globals before loading
        loader
            .override_global("BASE_KEY", &base_key, false)
            .override_global("SPICA_PID", &spica_pid, false)
            .override_global("INTEGRITY_TOKEN", &integrity_token, false);

        let mut bpf = loader.load(include_bytes_aligned!(
            concat!(env!("OUT_DIR"), "/spica")
        ))?;

        let btf = Btf::from_sys_fs()?;

        // Helper function to load and attach a program in one go
        fn load_and_attach_sched(bpf: &mut Ebpf, btf: &Btf) -> Result<()> {
            let prog: &mut BtfTracePoint = bpf.program_mut("spica_sched").unwrap().try_into()
                .map_err(|e| anyhow::anyhow!("failed to get sched program: {:?}", e))?;
            prog.load("sched_switch", btf)
                .map_err(|e| anyhow::anyhow!("failed to load sched program: {:?}", e))?;
            prog.attach()
                .map_err(|e| anyhow::anyhow!("failed to attach sched program: {:?}", e))?;
            Ok(())
        }

        fn load_and_attach_nmi(bpf: &mut Ebpf) -> Result<()> {
            let prog: &mut PerfEvent = bpf.program_mut("spica_nmi").unwrap().try_into()
                .map_err(|e| anyhow::anyhow!("failed to get nmi program: {:?}", e))?;
            prog.load()
                .map_err(|e| anyhow::anyhow!("failed to load nmi program: {:?}", e))?;
            let cpus = util::online_cpus().map_err(|(path, e)| {
                anyhow::anyhow!("failed to read online CPUs from {}: {}", path, e)
            })?;
            for cpu in cpus {
                prog.attach(
                    perf_event::PerfEventConfig::Hardware(perf_event::HardwareEvent::CpuCycles),
                    perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
                    perf_event::SamplePolicy::Period(10_000_000),
                    false,
                ).map_err(|e| anyhow::anyhow!("failed to attach nmi program: {:?}", e))?;
            }
            Ok(())
        }

        fn load_watchdog(bpf: &mut Ebpf) -> Result<()> {
            let prog: &mut TracePoint = bpf.program_mut("spica_watchdog").unwrap().try_into()
                .map_err(|e| anyhow::anyhow!("failed to get watchdog program: {:?}", e))?;
            prog.load()
                .map_err(|e| anyhow::anyhow!("failed to load watchdog program: {:?}", e))?;
            Ok(())
        }

        fn attach_watchdog(bpf: &mut Ebpf) -> Result<()> {
            let prog: &mut TracePoint = bpf.program_mut("spica_watchdog").unwrap().try_into()
                .map_err(|e| anyhow::anyhow!("failed to get watchdog program: {:?}", e))?;
            prog.attach("sched", "sched_process_exit")
                .map_err(|e| anyhow::anyhow!("failed to attach watchdog program: {:?}", e))?;
            Ok(())
        }

        fn load_lsm_if_needed(bpf: &mut Ebpf, btf: &Btf) -> Result<bool> {
            let lsm_attached = fs::read_to_string("/sys/kernel/security/lsm")
                .map(|s| s.contains("bpf"))
                .unwrap_or(false);
            if lsm_attached {
                let prog: &mut Lsm = bpf.program_mut("spica_lsm_modblock").unwrap().try_into()
                    .map_err(|e| anyhow::anyhow!("failed to get lsm program: {:?}", e))?;
                prog.load("kernel_read_file", btf)
                    .map_err(|e| anyhow::anyhow!("failed to load lsm program: {:?}", e))?;
            }
            Ok(lsm_attached)
        }

        fn attach_lsm_if_attached(bpf: &mut Ebpf, attached: bool) -> Result<()> {
            if attached {
                let prog: &mut Lsm = bpf.program_mut("spica_lsm_modblock").unwrap().try_into()
                    .map_err(|e| anyhow::anyhow!("failed to get lsm program: {:?}", e))?;
                prog.attach()
                    .map_err(|e| anyhow::anyhow!("failed to attach lsm program: {:?}", e))?;
            }
            Ok(())
        }

        // 1. Load all programs first
        load_watchdog(&mut bpf)?;
        let lsm_attached = load_lsm_if_needed(&mut bpf, &btf)?;

        // 2. Write canary BEFORE NMI attaches to avoid spurious TAMPER on startup.
        {
            let canary_map = bpf.take_map("sc_canary").unwrap();
            let mut canary: ArrayU64 = canary_map.try_into()
                .map_err(|e| anyhow::anyhow!("failed to convert canary map: {:?}", e))?;
            canary.set(0, integrity_token, 0)
                .map_err(|e| anyhow::anyhow!("failed to set canary: {:?}", e))?;
        }

        // 3. Attach observation channels in quick succession to minimize startup asymmetry
        load_and_attach_sched(&mut bpf, &btf)?;
        load_and_attach_nmi(&mut bpf)?;

        // 4. Attach remaining programs
        attach_watchdog(&mut bpf)?;
        attach_lsm_if_attached(&mut bpf, lsm_attached)?;

        // 5. Pin watchdog map to BPF-FS so it outlives a SIGKILL.
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
        let gate_map = self.bpf.take_map("sc_gate").unwrap();
        let mut gate: ArrayU32 = gate_map.try_into()?;
        gate.set(0, 1u32, 0)?;
        Ok(())
    }

    pub fn lsm_attached(&self) -> bool { self.lsm_attached }

    /// Split the runtime into its ring buffers for use in tokio::select!
    pub fn split_ring_buffers(
        &mut self,
    ) -> (&mut AsyncFd<RingBuf<MapData>>, &mut AsyncFd<RingBuf<MapData>>, &mut AsyncFd<RingBuf<MapData>>) {
        (&mut self.sched_rb, &mut self.nmi_rb, &mut self.lsm_rb)
    }
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

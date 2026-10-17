//! eBPF runtime lifecycle: load programs, attach, pin links, freeze maps,
//! manage ring buffers, pin watchdog.
//!
//! Load order is security-critical (each step shrinks the window in which a
//! racing rootkit could interfere):
//!
//!   0. Reap any leftover LINK pins from a previous instance (SIGKILL
//!      survival means pins outlive the daemon; unlinking the pin files
//!      detaches the old programs — otherwise two instances would double-
//!      attach every tracepoint).
//!   1. Load all programs (loader pre-sets SPICA_PID and AUTH_TOKEN).
//!   2. Attach observation channels (sched, fork, exit, NMI, watchdog) and
//!      PIN every link under /sys/fs/bpf/spica_links/ — attachments now
//!      survive SIGKILL of this process.
//!   3. Attach kernel_read_file LSM; close sc_gate (block new LKMs).
//!   4. Pin watchdog map.
//!   5. FREEZE `.bss`, `sc_gate`, `sc_wd`, `sc_ledger` via `BPF_MAP_FREEZE`
//!      — syscall writes (spoofing of chain state / gates / the auth token)
//!      return EPERM for the maps' lifetime; programs keep write access.
//!      Freeze is verified by re-freezing and expecting EPERM/EBUSY;
//!      failure aborts the load (fail-closed).
//!   6. Attach the deny-by-default `bpf()` LSM gate LAST — from this point
//!      every bpf() syscall from a non-SPiCa TGID is denied unless it
//!      carries the one-time uninstall token in its attr padding (knock),
//!      which opens a 60-second authorization window.
//!
//! Clean shutdown (SIGTERM) unpins everything — deliberate: an operator's
//! orderly stop disarms the protection. SIGKILL leaves it armed.

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    include_bytes_aligned,
    maps::{Map, MapData, RingBuf},
    programs::{links::FdLink, Lsm, PerfEvent, TracePoint, perf_event},
    util, Ebpf, EbpfLoader, Btf,
};
use std::fs;
use std::os::fd::{AsFd, AsRawFd};
use tokio::io::unix::AsyncFd;

pub const WATCHDOG_PIN: &str = "/sys/fs/bpf/spica_watchdog";
/// Link pins: one per attachment. Pinned links hold the attachment (and via
/// it, the program and its maps) alive even if the daemon is SIGKILLed.
pub const LINK_PIN_DIR: &str = "/sys/fs/bpf/spica_links";

/// Runtime status reported to main for fail-loud diagnostics.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeStatus {
    /// kernel_read_file hook attached: new LKM loads are blocked.
    pub modblock: bool,
    /// `bpf` hook attached: bpf() syscalls denied for non-SPiCa processes.
    pub bpfgate: bool,
    /// Notary on a hardware PMU event (true NMI context). False = software
    /// event fallback (VMs without a virtual PMU, some containers): the
    /// notary runs and chain cross-checks are intact, but the "unmaskable
    /// interrupt" hardening is absent — degraded mode, logged loudly.
    pub nmi_hw: bool,
}

pub struct BpfRuntime {
    #[allow(dead_code)] // owns the loaded programs; kept alive for detach-on-drop
    bpf: Ebpf,
    sched_rb: AsyncFd<RingBuf<MapData>>,
    nmi_rb: AsyncFd<RingBuf<MapData>>,
    lsm_rb: AsyncFd<RingBuf<MapData>>,
    status: RuntimeStatus,
}

impl BpfRuntime {
    /// Load eBPF, attach + pin programs, freeze maps, take ring buffers.
    ///
    /// `auth_token` is the one-time uninstall token, baked into frozen
    /// `.bss` pre-load: only a valid knock (same 32 bytes in a gated bpf()
    /// call's attr padding) can open the authorization window afterwards.
    pub fn load(spica_pid: u32, auth_token: [u8; 32]) -> Result<Self> {
        // 0. Reap leftover link pins from a previous (SIGKILLed) instance.
        if fs::metadata(LINK_PIN_DIR).is_ok() {
            println!("[WATCHDOG]   Leftover link pins found — previous instance was SIGKILLed; reaping (attachments transfer to this instance)");
            remove_link_pins();
        }
        fs::create_dir_all(LINK_PIN_DIR).context("create link pin dir")?;

        let mut loader = EbpfLoader::new();
        loader.override_global("SPICA_PID", &spica_pid, false);
        loader.override_global("AUTH_TOKEN", &auth_token, false);

        let mut bpf = loader.load(include_bytes_aligned!(
            concat!(env!("OUT_DIR"), "/spica")
        ))?;

        let btf = Btf::from_sys_fs()?;
        let lsm_available = fs::read_to_string("/sys/kernel/security/lsm")
            .map(|s| s.contains("bpf"))
            .unwrap_or(false);

        fn pin_path(name: &str, idx: usize) -> String {
            format!("{LINK_PIN_DIR}/{name}_{idx}")
        }

        fn load_and_pin_tp(bpf: &mut Ebpf, name: &str, cat: &str, tp: &str) -> Result<()> {
            let prog: &mut TracePoint = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("program {name} not found"))?
                .try_into()
                .map_err(|e| anyhow!("failed to get {name}: {e:?}"))?;
            prog.load().map_err(|e| anyhow!("failed to load {name}: {e:?}"))?;
            let id = prog
                .attach(cat, tp)
                .map_err(|e| anyhow!("failed to attach {name}: {e:?}"))?;
            let link = prog.take_link(id).map_err(|e| anyhow!("take_link {name}: {e:?}"))?;
            let fd_link: FdLink = link
                .try_into()
                .map_err(|e: aya::programs::links::LinkError| anyhow!("fd link {name}: {e:?}"))?;
            fd_link
                .pin(pin_path(name, 0))
                .map_err(|e| anyhow!("pin {name}: {e:?}"))?;
            Ok(())
        }

        fn load_and_pin_nmi(bpf: &mut Ebpf) -> Result<bool> {
            let prog: &mut PerfEvent = bpf.program_mut("spica_nmi").unwrap().try_into()
                .map_err(|e| anyhow!("failed to get nmi program: {:?}", e))?;
            prog.load()
                .map_err(|e| anyhow!("failed to load nmi program: {:?}", e))?;
            let cpus = util::online_cpus().map_err(|(path, e)| {
                anyhow!("failed to read online CPUs from {}: {}", path, e)
            })?;
            let hw = perf_event::PerfEventConfig::Hardware(perf_event::HardwareEvent::CpuCycles);
            let sw = perf_event::PerfEventConfig::Software(perf_event::SoftwareEvent::CpuClock);
            for (config, is_hw) in [(hw, true), (sw, false)] {
                let mut ids = Vec::new();
                let mut ok = true;
                for cpu in &cpus {
                    match prog.attach(
                        config,
                        perf_event::PerfEventScope::AllProcessesOneCpu { cpu: *cpu },
                        perf_event::SamplePolicy::Period(10_000_000),
                        false,
                    ) {
                        Ok(id) => ids.push(id),
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    for (i, id) in ids.into_iter().enumerate() {
                        let link = prog
                            .take_link(id)
                            .map_err(|e| anyhow!("take nmi link: {e:?}"))?;
                        let fd_link: FdLink = link
                            .try_into()
                            .map_err(|e: aya::programs::links::LinkError| anyhow!("fd nmi link: {e:?}"))?;
                        fd_link
                            .pin(pin_path("nmi", i))
                            .map_err(|e| anyhow!("pin nmi link: {e:?}"))?;
                    }
                    return Ok(is_hw);
                }
            }
            bail!("notary attach failed: neither hardware PMU nor software fallback available");
        }

        fn load_lsm(bpf: &mut Ebpf, prog_name: &str, hook: &str, btf: &Btf) -> Result<()> {
            let prog: &mut Lsm = bpf.program_mut(prog_name).unwrap().try_into()
                .map_err(|e| anyhow!("failed to get {prog_name}: {:?}", e))?;
            prog.load(hook, btf)
                .map_err(|e| anyhow!("failed to load {prog_name} on {hook}: {:?}", e))?;
            Ok(())
        }

        fn attach_and_pin_lsm(bpf: &mut Ebpf, prog_name: &str) -> Result<()> {
            let prog: &mut Lsm = bpf.program_mut(prog_name).unwrap().try_into()
                .map_err(|e| anyhow!("failed to get {prog_name}: {:?}", e))?;
            let id = prog.attach()
                .map_err(|e| anyhow!("failed to attach {prog_name}: {:?}", e))?;
            let link = prog.take_link(id).map_err(|e| anyhow!("take_link {prog_name}: {e:?}"))?;
            let fd_link: FdLink = link.into();
            fd_link
                .pin(pin_path(prog_name, 0))
                .map_err(|e| anyhow!("pin {prog_name}: {e:?}"))?;
            Ok(())
        }

        // 1. Attach + pin all observation channels.
        load_and_pin_tp(&mut bpf, "spica_sched", "sched", "sched_switch")?;
        load_and_pin_tp(&mut bpf, "spica_fork", "sched", "sched_process_fork")?;
        load_and_pin_tp(&mut bpf, "spica_exit", "sched", "sched_process_exit")?;
        load_and_pin_tp(&mut bpf, "spica_watchdog", "sched", "sched_process_exit")?;
        let nmi_hw = load_and_pin_nmi(&mut bpf)?;

        // 2. LSM: kernel_read_file gate (LKM blocking). Close, then freeze.
        let mut status = RuntimeStatus { nmi_hw, ..Default::default() };
        if lsm_available {
            load_lsm(&mut bpf, "spica_lsm_modblock", "kernel_read_file", &btf)?;
            attach_and_pin_lsm(&mut bpf, "spica_lsm_modblock")?;
            status.modblock = true;
            close_and_freeze_gate(&mut bpf)?;
        }

        // 3. Pin the watchdog map so it outlives a SIGKILL.
        bpf.map("sc_wd").unwrap().pin(WATCHDOG_PIN)?;

        // 4. Freeze all program-written state. Fail-closed on any error.
        //    NOTE: #[used]+export_name globals (SPICA_PID, AUTH_TOKEN) land
        //    in their own `.bss.<SYMBOL>` maps — every .bss* map must be
        //    sealed, or the split ones stay syscall-writable (found in the
        //    VM round: SPICA_PID unfrozen = gate bypassable by rewrite).
        //    Missing names are skipped; present ones MUST freeze.
        let mut bss_sealed = 0;
        for name in [".bss", ".bss.SPICA_PID", ".bss.AUTH_TOKEN"] {
            if bpf.map(name).is_some() {
                freeze_map(&bpf, name)
                    .with_context(|| format!("freeze {name} (chain state / pid / token)"))?;
                bss_sealed += 1;
            }
        }
        if bss_sealed == 0 {
            bail!("no .bss maps found — unexpected object layout");
        }
        freeze_map(&bpf, "sc_ledger").context("freeze sc_ledger (evidence ring)")?;
        freeze_map(&bpf, "sc_wd").context("freeze sc_wd (kill flag)")?;

        // 5. Attach the deny-by-default bpf() gate LAST.
        if lsm_available {
            match load_lsm(&mut bpf, "spica_lsm_bpfgate", "bpf", &btf)
                .and_then(|()| attach_and_pin_lsm(&mut bpf, "spica_lsm_bpfgate"))
            {
                Ok(()) => status.bpfgate = true,
                Err(e) => {
                    eprintln!(
                        "[LSM]        WARNING: bpf() gate did not attach ({e}); \
                         SPiCa objects remain enumerable by CAP_SYS_ADMIN"
                    );
                }
            }
        }

        // 6. Take ring buffers into AsyncFd.
        let sched_rb = AsyncFd::new(RingBuf::try_from(bpf.take_map("sc_sched").unwrap())?)?;
        let nmi_rb = AsyncFd::new(RingBuf::try_from(bpf.take_map("sc_nmi").unwrap())?)?;
        let lsm_rb = AsyncFd::new(RingBuf::try_from(bpf.take_map("sc_lsm").unwrap())?)?;

        Ok(Self { bpf, sched_rb, nmi_rb, lsm_rb, status })
    }

    pub fn status(&self) -> RuntimeStatus {
        self.status
    }

    /// Split the runtime into its ring buffers for use in tokio::select!
    pub fn split_ring_buffers(
        &mut self,
    ) -> (&mut AsyncFd<RingBuf<MapData>>, &mut AsyncFd<RingBuf<MapData>>, &mut AsyncFd<RingBuf<MapData>>) {
        (&mut self.sched_rb, &mut self.nmi_rb, &mut self.lsm_rb)
    }
}

// ── Gate close + freeze helpers ──────────────────────────────────────────────

/// Set sc_gate[0] = 1 (block all new LKM loads) and freeze the map so the
/// gate can never be reopened or spoofed via the syscall path.
fn close_and_freeze_gate(bpf: &mut Ebpf) -> Result<()> {
    // Capture the map id while the map is still owned by `bpf`.
    let id = {
        let map = bpf
            .map("sc_gate")
            .ok_or_else(|| anyhow!("sc_gate not found"))?;
        let md: &MapData = match map {
            Map::Array(md) => md,
            _ => bail!("sc_gate is not an Array"),
        };
        md.info()?.id()
    };
    // Write before freezing — update_elem on a frozen map is EPERM. If this
    // write fails with EPERM, an attacker already froze the gate open during
    // the load window: fail-closed.
    let gate_map = bpf
        .take_map("sc_gate")
        .ok_or_else(|| anyhow!("sc_gate disappeared"))?;
    let mut gate: aya::maps::Array<MapData, u32> = gate_map.try_into()?;
    gate.set(0, 1u32, 0)
        .context("close sc_gate (attacker may have frozen it open — aborting)")?;
    freeze_by_id(id, "sc_gate")
}

/// Freeze a named map. Fails closed if the map is missing. The fd is
/// obtained fresh via BPF_MAP_GET_FD_BY_ID (aya's MapInfo::fd); it is
/// deliberately never closed — it is the daemon's freeze handle (bounded:
/// one fd per frozen map).
fn freeze_map(bpf: &Ebpf, name: &str) -> Result<()> {
    let map = bpf.map(name).ok_or_else(|| anyhow!("map {name} not found"))?;
    let md: &MapData = match map {
        Map::Array(md) => md,
        _ => bail!("map {name} is not an Array"),
    };
    let fd = md.info().with_context(|| format!("info for {name}"))?.fd()
        .with_context(|| format!("fd for {name}"))?;
    freeze_fd(fd.as_fd().as_raw_fd(), name)
}

/// Freeze a map by id (same handle strategy as `freeze_map`).
fn freeze_by_id(id: u32, name: &str) -> Result<()> {
    let info = aya::maps::MapInfo::from_id(id).with_context(|| format!("info for {name}"))?;
    let fd = info.fd().with_context(|| format!("fd for {name}"))?;
    freeze_fd(fd.as_fd().as_raw_fd(), name)
}

/// Raw BPF_MAP_FREEZE. aya 0.13 does not expose it publicly (it only freezes
/// `.rodata` internally during load).
fn freeze_fd(fd: i32, name: &str) -> Result<()> {
    const BPF_MAP_FREEZE: libc::c_long = 22;
    // bpf_attr union: __u32 map_fd at offset 0. 128 bytes is ample.
    let mut attr = [0u64; 16];
    attr[0] = fd as u32 as u64;
    // SAFETY: plain bpf() syscall with a valid map fd.
    let r = unsafe { libc::syscall(libc::SYS_bpf, BPF_MAP_FREEZE, attr.as_mut_ptr(), attr.len() * 8) };
    if r < 0 {
        return Err(anyhow!(std::io::Error::last_os_error()))
            .with_context(|| format!("BPF_MAP_FREEZE({name})"));
    }
    // Verify the freeze took by freezing again. The observable on v6.8 is
    // EPERM: freezing strips FMODE_CAN_WRITE from the fd (map_get_sys_perms),
    // so a second attempt fails the permissions check before the kernel's
    // already-frozen EBUSY path is reached. EBUSY is accepted for older
    // kernels/reordered checks. A second freeze that *succeeds* means the
    // map is not sealed — spoofable state, abort.
    let r2 = unsafe { libc::syscall(libc::SYS_bpf, BPF_MAP_FREEZE, attr.as_mut_ptr(), attr.len() * 8) };
    let sealed = r2 < 0
        && matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM) | Some(libc::EBUSY)
        );
    if !sealed {
        bail!("freeze verification failed for {name}: map is not sealed");
    }
    Ok(())
}

// ── Knock (uninstall authorization) ──────────────────────────────────────────

/// BPF_MAP_GET_FD_BY_ID — harmless carrier command for the knock (its attr
/// leaves offset 96 untouched).
const BPF_MAP_GET_FD_BY_ID: libc::c_long = 14;
/// Offset of the 32-byte token within bpf_attr (must match the eBPF side).
pub const KNOCK_ATTR_OFFSET: usize = 96;

/// Attempt the uninstall knock: a gated bpf() call carrying the token in
/// attr padding. Returns Ok(()) if authorized (or if no gate is armed),
/// Err(reason) if the gate rejected the token.
pub fn knock(auth_token: &[u8; 32]) -> Result<(), String> {
    let mut attr = [0u64; 16];
    attr[0] = u32::MAX as u64; // map_id: deliberately invalid
    attr[KNOCK_ATTR_OFFSET / 8..KNOCK_ATTR_OFFSET / 8 + 4]
        .copy_from_slice(bytemuck_const(auth_token));
    // SAFETY: plain bpf() syscall.
    let r = unsafe {
        libc::syscall(libc::SYS_bpf, BPF_MAP_GET_FD_BY_ID, attr.as_mut_ptr(), attr.len() * 8)
    };
    let err = std::io::Error::last_os_error();
    match r {
        _ if r >= 0 => {
            // fd returned for id u32::MAX?? treat as gate-absent anomaly; close fd
            #[allow(unused_must_use)]
            {
                if let Ok(fd) = i32::try_from(r) {
                    unsafe { libc::close(fd) };
                }
            }
            Ok(())
        }
        _ if err.raw_os_error() == Some(libc::EPERM) => {
            Err("bpf() gate rejected the token (wrong token, or window closed)".to_string())
        }
        // Gate absent (or token accepted but the invalid map id failed):
        // EBADF/EINVAL/ENOENT mean the call passed the gate and failed in
        // map lookup — the knock was accepted.
        _ => Ok(()),
    }
}

/// Stable, dependency-free byte view of the token.
fn bytemuck_const(t: &[u8; 32]) -> &[u64; 4] {
    // SAFETY: [u8;32] and [u64;4] have identical size/alignment compatibility
    // (both 32 bytes; u64 alignment divides the array's alignment).
    unsafe { &*(t.as_ptr() as *const [u64; 4]) }
}

// ── Watchdog + link pin helpers ──────────────────────────────────────────────

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

/// Remove all link pins (detaches every program of a previous/pinned
/// instance). Called on clean shutdown and at startup to reap a SIGKILLed
/// predecessor.
pub fn remove_link_pins() {
    if let Ok(entries) = fs::read_dir(LINK_PIN_DIR) {
        for e in entries.flatten() {
            let _ = fs::remove_file(e.path());
        }
    }
}

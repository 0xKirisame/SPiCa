use aya::{include_bytes_aligned, Bpf};
use aya::maps::RingBuf;
use aya::programs::{BtfTracePoint, PerfEvent, PerfTypeId, perf_event::PerfEventScope, perf_event::SamplePolicy};
use spica_common::ProcessInfo;
use std::{
    collections::{HashMap, HashSet},
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant},
};
use tokio::io::unix::AsyncFd;

/// Poll cadence — also the outer select timeout.
const TICK_RATE_MS: u64 = 100;
/// Seconds a TGID must remain suspicious before alerting.
const SUSPECT_THRESHOLD_SECS: u64 = 2;
/// Grace window: ignore events for TGIDs seen more recently than this.
/// Replaces the implicit ~1 s grace that the old 1-second poll provided.
const GRACE_WINDOW_MS: u64 = 50;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/spica"
    ))?;

    // --- Attach BTF tracepoint (sched_switch) ---
    let sched_prog: &mut BtfTracePoint = bpf
        .program_mut("spica_sched")
        .unwrap()
        .try_into()?;
    sched_prog.load()?;
    sched_prog.attach("sched_switch")?;

    // --- Attach NMI perf-event (hardware CPU cycle counter) ---
    // Attaches to all CPUs; fired via PMU/NMI, not maskable in software.
    let nmi_prog: &mut PerfEvent = bpf
        .program_mut("spica_nmi")
        .unwrap()
        .try_into()?;
    nmi_prog.load()?;
    nmi_prog.attach(
        PerfTypeId::Hardware,
        aya::programs::perf_event::perf_hw_id::PERF_COUNT_HW_CPU_CYCLES as u64,
        PerfEventScope::AllProcessesOneCpu { cpu: 0 },
        SamplePolicy::Frequency(1000),
        true,
    )?;

    println!("I'm going to sing, so shine bright, SPiCa...");
    println!("Channels: sched_switch (BTF/CO-RE) + NMI perf-event");

    // --- Open ring buffers ---
    let sched_rb = RingBuf::try_from(bpf.map_mut("EVENTS_SCHED").unwrap())?;
    let nmi_rb   = RingBuf::try_from(bpf.map_mut("EVENTS_NMI").unwrap())?;

    let mut sched_fd = AsyncFd::new(sched_rb)?;
    let mut nmi_fd   = AsyncFd::new(nmi_rb)?;

    // tgid → Instant of first observation per channel
    let mut sched_seen: HashMap<u32, Instant> = HashMap::new();
    let mut nmi_seen:   HashMap<u32, Instant> = HashMap::new();

    // tgid → Instant it first became suspicious (absent from /proc)
    let mut suspects: HashMap<u32, Instant> = HashMap::new();

    loop {
        tokio::select! {
            // sched_switch ring buffer is readable
            guard = sched_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let info = unsafe { &*(item.as_ptr() as *const ProcessInfo) };
                    process_event(
                        info,
                        &mut sched_seen,
                        &mut nmi_seen,
                        &mut suspects,
                        Channel::Sched,
                    );
                }
                guard.clear_ready();
            }

            // NMI ring buffer is readable
            guard = nmi_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let info = unsafe { &*(item.as_ptr() as *const ProcessInfo) };
                    process_event(
                        info,
                        &mut sched_seen,
                        &mut nmi_seen,
                        &mut suspects,
                        Channel::Nmi,
                    );
                }
                guard.clear_ready();
            }

            // Periodic tick: run detection logic
            _ = tokio::time::sleep(Duration::from_millis(TICK_RATE_MS)) => {
                run_detection(&mut sched_seen, &mut nmi_seen, &mut suspects);
            }

            // Graceful shutdown
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down SPiCa.");
                break;
            }
        }
    }

    Ok(())
}

enum Channel { Sched, Nmi }

/// Record that a TGID was observed on the given channel.
fn process_event(
    info: &ProcessInfo,
    sched_seen: &mut HashMap<u32, Instant>,
    nmi_seen:   &mut HashMap<u32, Instant>,
    suspects:   &mut HashMap<u32, Instant>,
    channel:    Channel,
) {
    let tgid = info.tgid;
    if tgid == 0 { return; }

    match channel {
        Channel::Sched => { sched_seen.entry(tgid).or_insert_with(Instant::now); }
        Channel::Nmi   => { nmi_seen.entry(tgid).or_insert_with(Instant::now); }
    }

    // If the TGID has reappeared in /proc, clear any suspect entry.
    if proc_has_tgid(tgid) {
        suspects.remove(&tgid);
    }
}

/// Main detection pass, run on each tick.
fn run_detection(
    sched_seen: &mut HashMap<u32, Instant>,
    nmi_seen:   &mut HashMap<u32, Instant>,
    suspects:   &mut HashMap<u32, Instant>,
) {
    let user_tgids = read_proc_tgids();
    let grace = Duration::from_millis(GRACE_WINDOW_MS);
    let suspect_threshold = Duration::from_secs(SUSPECT_THRESHOLD_SECS);
    let now = Instant::now();

    // 1. PROBE_TAMPER check: NMI sees a TGID that sched_switch has never reported.
    //    This means the sched_switch hook output is being cleaned for that process.
    for (&tgid, nmi_first) in nmi_seen.iter() {
        if nmi_first.elapsed() < grace { continue; }
        if !sched_seen.contains_key(&tgid) {
            // NMI sees it, sched never did — probe tamper
            let comm = resolve_comm(tgid);
            println!(
                "[PROBE_TAMPER] TGID: {} | NAME: {} | sched_switch probe suppressed for this process",
                tgid, comm
            );
        }
    }

    // 2. DKOM + MASQUERADE checks: iterate all kernel-observed TGIDs.
    let all_tgids: HashSet<u32> = sched_seen.keys().chain(nmi_seen.keys()).copied().collect();

    for tgid in all_tgids {
        let first_seen = sched_seen.get(&tgid).or_else(|| nmi_seen.get(&tgid)).copied().unwrap();
        if first_seen.elapsed() < grace { continue; }

        if !user_tgids.contains(&tgid) {
            // Not in /proc — confirm it's still scheduling (liveness)
            let alive_in_kernel = sched_seen.get(&tgid)
                .map(|t| t.elapsed() < Duration::from_millis(500))
                .unwrap_or(false)
                || nmi_seen.get(&tgid)
                    .map(|t| t.elapsed() < Duration::from_millis(500))
                    .unwrap_or(false);

            if !alive_in_kernel { continue; }

            let entry = suspects.entry(tgid).or_insert(now);
            if entry.elapsed() > suspect_threshold {
                let comm = resolve_comm(tgid);
                println!(
                    "[DKOM] TGID: {} | NAME: {} | HIDDEN FOR: {:?}",
                    tgid, comm, entry.elapsed()
                );
            }
        } else {
            suspects.remove(&tgid);

            // 3. MASQUERADE: compare kernel comm (from NMI/sched event) against /proc exe.
            check_masquerade(tgid);
        }
    }

    // 4. GC: remove TGIDs that haven't been observed on either channel recently.
    let stale = Duration::from_secs(10);
    sched_seen.retain(|_, t| t.elapsed() < stale);
    nmi_seen.retain(|_, t| t.elapsed() < stale);
    suspects.retain(|tgid, _| {
        sched_seen.contains_key(tgid) || nmi_seen.contains_key(tgid)
    });
}

/// Read /proc and return the set of numeric TGIDs.
fn read_proc_tgids() -> HashSet<u32> {
    let mut set = HashSet::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(n) = entry.file_name().to_string_lossy().parse::<u32>() {
                set.insert(n);
            }
        }
    }
    set
}

fn proc_has_tgid(tgid: u32) -> bool {
    Path::new(&format!("/proc/{}", tgid)).exists()
}

/// Read /proc/{tgid}/comm for the process name as reported by the VFS.
fn resolve_comm(tgid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", tgid))
        .unwrap_or_else(|_| "???".into())
        .trim()
        .to_string()
}

/// Compare kernel comm (from /proc/{tgid}/status Name field) against the
/// actual executable basename from /proc/{tgid}/exe.
/// A mismatch after the grace window indicates PID hollowing / masquerade.
fn check_masquerade(tgid: u32) {
    let kernel_comm = fs::read_to_string(format!("/proc/{}/comm", tgid))
        .unwrap_or_default();
    let kernel_comm = kernel_comm.trim();
    if kernel_comm.is_empty() { return; }

    let exe_path = match fs::read_link(format!("/proc/{}/exe", tgid)) {
        Ok(p) => p,
        Err(_) => return,
    };

    let exe_name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // comm is truncated to 15 chars by the kernel; compare against that prefix.
    let comm_prefix = if kernel_comm.len() > 15 { &kernel_comm[..15] } else { kernel_comm };
    let exe_prefix  = if exe_name.len() > 15   { &exe_name[..15]    } else { exe_name };

    if !exe_prefix.is_empty() && comm_prefix != exe_prefix {
        println!(
            "[MASQUERADE] TGID: {} | KERNEL_COMM: {} | ACTUAL_EXE: {}",
            tgid, kernel_comm, exe_path.display()
        );
    }
}

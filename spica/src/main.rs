#![allow(deprecated)] // aya renames Bpf → Ebpf in newer versions

use aya::{include_bytes_aligned, Bpf, Btf};
use aya::maps::{Array, RingBuf};
use aya::programs::{
    BtfTracePoint, PerfEvent,
    perf_event::{HardwareEvent, PerfEventConfig, PerfEventScope, SamplePolicy},
};
use spica_common::ProcessInfo;
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    path::Path,
    time::{Duration, Instant},
};
use tokio::io::unix::AsyncFd;

const TICK_RATE_MS: u64 = 100;
const SUSPECT_THRESHOLD_SECS: u64 = 2;
const GRACE_WINDOW_MS: u64 = 50;
const ALERT_COOLDOWN_SECS: u64 = 30;

// ── Detection logic ──────────────────────────────────────────────────────────

// Observation maps store (first_seen, last_seen).
// first_seen: used for grace window — don't alert on brand-new processes.
// last_seen:  updated on every event — used for liveness and stale eviction.
type SeenMap = HashMap<u32, (Instant, Instant)>;

enum Channel { Sched, Nmi }

fn process_event(
    info: &ProcessInfo,
    sched_seen: &mut SeenMap,
    nmi_seen: &mut SeenMap,
    suspects: &mut HashMap<u32, Instant>,
    channel: Channel,
) {
    let tgid = info.tgid;
    if tgid == 0 { return; }
    let now = Instant::now();
    match channel {
        Channel::Sched => {
            sched_seen.entry(tgid)
                .and_modify(|e| e.1 = now)
                .or_insert((now, now));
        }
        Channel::Nmi => {
            nmi_seen.entry(tgid)
                .and_modify(|e| e.1 = now)
                .or_insert((now, now));
        }
    }
    if proc_has_tgid(tgid) {
        suspects.remove(&tgid);
    }
}

fn run_detection(
    sched_seen: &mut SeenMap,
    nmi_seen: &mut SeenMap,
    suspects: &mut HashMap<u32, Instant>,
    tamper_alerted: &mut HashMap<u32, Instant>,
    dkom_alerted: &mut HashMap<u32, Instant>,
) {
    let user_tgids = read_proc_tgids();
    let grace = Duration::from_millis(GRACE_WINDOW_MS);
    let suspect_threshold = Duration::from_secs(SUSPECT_THRESHOLD_SECS);
    let cooldown = Duration::from_secs(ALERT_COOLDOWN_SECS);
    let now = Instant::now();

    // [TAMPER]: NMI sees a process but sched_switch never has.
    // Uses first_seen for grace (don't fire immediately on startup) and checks
    // a per-tgid cooldown so the same process doesn't flood the alert log.
    for (&tgid, &(nmi_first, _)) in nmi_seen.iter() {
        if nmi_first.elapsed() < grace { continue; }
        if !sched_seen.contains_key(&tgid) {
            let should_alert = tamper_alerted.get(&tgid)
                .map(|t| t.elapsed() > cooldown)
                .unwrap_or(true);
            if should_alert {
                tamper_alerted.insert(tgid, now);
                let comm = resolve_comm(tgid);
                println!("[TAMPER]     tgid:{:<6} {:<16} sched_switch suppressed", tgid, comm);
            }
        } else {
            // Process is now visible in sched_switch — clear any past tamper alert
            // so it can be re-alerted if suppression starts again later.
            tamper_alerted.remove(&tgid);
        }
    }

    // [DKOM]: scan everything we've ever seen.
    let all_tgids: HashSet<u32> = sched_seen.keys().chain(nmi_seen.keys()).copied().collect();
    for tgid in all_tgids {
        let (first_seen, _) = sched_seen.get(&tgid)
            .or_else(|| nmi_seen.get(&tgid))
            .copied()
            .unwrap();
        if first_seen.elapsed() < grace { continue; }

        if !user_tgids.contains(&tgid) {
            // Use last_seen for liveness — a process is alive if it was observed
            // recently, regardless of when it first appeared.
            let alive = sched_seen.get(&tgid)
                .map(|(_, last)| last.elapsed() < Duration::from_millis(500))
                .unwrap_or(false)
                || nmi_seen.get(&tgid)
                    .map(|(_, last)| last.elapsed() < Duration::from_millis(500))
                    .unwrap_or(false);
            if !alive { continue; }

            let entry = suspects.entry(tgid).or_insert(now);
            if entry.elapsed() > suspect_threshold {
                let should_alert = dkom_alerted.get(&tgid)
                    .map(|t| t.elapsed() > cooldown)
                    .unwrap_or(true);
                if should_alert {
                    dkom_alerted.insert(tgid, now);
                    let comm = resolve_comm(tgid);
                    let duration = format!("{:.1}s", entry.elapsed().as_secs_f64());
                    println!("[DKOM]       tgid:{:<6} {:<16} hidden {}", tgid, comm, duration);
                }
            }
        } else {
            suspects.remove(&tgid);
            dkom_alerted.remove(&tgid);
        }
    }

    // Stale eviction: use last_seen so long-running processes aren't evicted.
    let stale = Duration::from_secs(10);
    sched_seen.retain(|_, (_, last)| last.elapsed() < stale);
    nmi_seen.retain(|_, (_, last)| last.elapsed() < stale);
    suspects.retain(|tgid, _| sched_seen.contains_key(tgid) || nmi_seen.contains_key(tgid));
    tamper_alerted.retain(|tgid, _| nmi_seen.contains_key(tgid));
    dkom_alerted.retain(|tgid, _| sched_seen.contains_key(tgid) || nmi_seen.contains_key(tgid));
}

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

fn resolve_comm(tgid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", tgid))
        .unwrap_or_else(|_| "???".into())
        .trim()
        .to_string()
}

fn urandom_u64() -> Result<u64, std::io::Error> {
    let mut buf = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/spica"
    ))?;

    let btf = Btf::from_sys_fs()?;
    let sched_prog: &mut BtfTracePoint = bpf.program_mut("spica_sched").unwrap().try_into()?;
    sched_prog.load("sched_switch", &btf)?;
    sched_prog.attach()?;

    let nmi_prog: &mut PerfEvent = bpf.program_mut("spica_nmi").unwrap().try_into()?;
    nmi_prog.load()?;
    nmi_prog.attach(
        PerfEventConfig::Hardware(HardwareEvent::CpuCycles),
        PerfEventScope::AllProcessesOneCpu { cpu: 0 },
        SamplePolicy::Frequency(1000),
        true,
    )?;

    let sched_rb = RingBuf::try_from(bpf.take_map("EVENTS_SCHED").unwrap())?;
    let nmi_rb   = RingBuf::try_from(bpf.take_map("EVENTS_NMI").unwrap())?;
    let mut sched_fd = AsyncFd::new(sched_rb)?;
    let mut nmi_fd   = AsyncFd::new(nmi_rb)?;

    // Generate a u64 obfuscation key from /dev/urandom.
    // Low 32 bits → XOR'd with pid, high 32 bits → XOR'd with tgid.
    // The eBPF programs read this key and obfuscate before writing to ring buffers,
    // so any rootkit hook filtering on raw PID values sees only noise.
    let mut obf_key: u64 = urandom_u64()?;
    let mut config_map = Array::<_, u64>::try_from(bpf.take_map("CONFIG").unwrap())?;
    config_map.set(0, obf_key, 0)?;
    let mut pid_key  = obf_key as u32;
    let mut tgid_key = (obf_key >> 32) as u32;

    let mut sched_seen: SeenMap = HashMap::new();
    let mut nmi_seen:   SeenMap = HashMap::new();
    let mut suspects:   HashMap<u32, Instant> = HashMap::new();
    let mut tamper_alerted: HashMap<u32, Instant> = HashMap::new();
    let mut dkom_alerted:   HashMap<u32, Instant> = HashMap::new();

    // Seed sched_seen with all processes already running at startup.
    // Without this, long-running processes (drivers, daemons) would appear in
    // NMI immediately but not in sched_seen until their next context switch,
    // causing spurious TAMPER alerts during the grace window.
    let startup = Instant::now();
    for tgid in read_proc_tgids() {
        sched_seen.insert(tgid, (startup, startup));
    }

    println!("I'm going to sing, so shine bright, SPiCa...");
    println!("SPiCa running — press Ctrl+C to quit");

    // ── Main loop ────────────────────────────────────────────────────────────
    let mut tick   = tokio::time::interval(Duration::from_millis(TICK_RATE_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut rotate = tokio::time::interval(Duration::from_secs(3600));
    rotate.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            guard = sched_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let raw = unsafe { &*(item.as_ptr() as *const ProcessInfo) };
                    let info = ProcessInfo {
                        pid:  raw.pid  ^ pid_key,
                        tgid: raw.tgid ^ tgid_key,
                        comm: raw.comm,
                        last_seen: raw.last_seen,
                    };
                    process_event(&info, &mut sched_seen, &mut nmi_seen, &mut suspects, Channel::Sched);
                }
                guard.clear_ready();
            }
            guard = nmi_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let raw = unsafe { &*(item.as_ptr() as *const ProcessInfo) };
                    let info = ProcessInfo {
                        pid:  raw.pid  ^ pid_key,
                        tgid: raw.tgid ^ tgid_key,
                        comm: raw.comm,
                        last_seen: raw.last_seen,
                    };
                    process_event(&info, &mut sched_seen, &mut nmi_seen, &mut suspects, Channel::Nmi);
                }
                guard.clear_ready();
            }
            _ = tick.tick() => {
                run_detection(&mut sched_seen, &mut nmi_seen, &mut suspects, &mut tamper_alerted, &mut dkom_alerted);
            }
            _ = rotate.tick() => {
                obf_key  = urandom_u64()?;
                config_map.set(0, obf_key, 0)?;
                pid_key  = obf_key as u32;
                tgid_key = (obf_key >> 32) as u32;
                println!("[SPICA]      obfuscation key rotated");
            }
            _ = tokio::signal::ctrl_c() => { break; }
        }
    }

    println!("Catch me! I'll leap over Denebola");

    Ok(())
}

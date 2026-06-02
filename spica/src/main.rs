#![allow(deprecated)] // aya renames Bpf → Ebpf in newer versions

use aya::{include_bytes_aligned, Bpf, Btf, util};
use aya::maps::{Array, RingBuf};
use aya::programs::{BtfTracePoint, Lsm, PerfEvent, TracePoint, Xdp, XdpFlags, perf_event};
use siphasher::sip::SipHasher13;
use spica_common::{LkmEvent, ProcessInfo};
use std::{
    collections::{HashMap, HashSet},
    fs,
    hash::Hasher,
    time::{Duration, Instant},
};
use tokio::io::unix::AsyncFd;
use tokio::signal::unix::{signal, SignalKind};

include!(concat!(env!("OUT_DIR"), "/keys.rs"));

const TICK_RATE_MS:           u64 = 100;
const SUSPECT_THRESHOLD_SECS: u64 = 2;
const GRACE_WINDOW_MS:        u64 = 50;
const ALERT_COOLDOWN_SECS:    u64 = 30;
const GHOST_THRESHOLD_SECS:   u64 = 5;

const WATCHDOG_PIN: &str = "/sys/fs/bpf/spica_watchdog";

// Derives the integrity canary from BASE_KEY using SipHash-1-3 so that
// sc_canary[0] (an enumerable map) does not leak BASE_KEY.
// XOR derivation was trivially invertible: canary ^ salt = BASE_KEY.
fn derive_integrity_token(base_key: u64) -> u64 {
    let key_bytes = base_key.to_ne_bytes();
    let mut k = [0u8; 16];
    k[..8].copy_from_slice(&key_bytes);
    k[8..].copy_from_slice(&key_bytes);
    let mut h = SipHasher13::new_with_key(&k);
    h.write(b"SPiCaINT");
    h.finish()
}

// ── Data model ────────────────────────────────────────────────────────────────

struct AlertState {
    last_dkom:      Option<Instant>,
    last_ghost:     Option<Instant>,
    last_tamper:    Option<Instant>,
    last_silent:    Option<Instant>,
}

struct ProcessRecord {
    start_time_ns:        u64,
    first_seen:           Instant,
    sched_last_seen:      Option<Instant>,
    nmi_last_seen:        Option<Instant>,
    dkom_suspect_since:   Option<Instant>,
    ghost_suspect_since:  Option<Instant>,
    tamper_suspect_since: Option<Instant>,
    silent_suspect_since: Option<Instant>,
    alerts:               AlertState,
}

type ProcessRegistry = HashMap<u32, ProcessRecord>;

// ── Detection logic ───────────────────────────────────────────────────────────

fn process_event(info: &ProcessInfo, registry: &mut ProcessRegistry, is_nmi: bool) {
    if info.tgid == 0 { return; }
    let now = Instant::now();

    let record = registry.entry(info.tgid).or_insert_with(|| ProcessRecord {
        start_time_ns:        info.start_time_ns,
        first_seen:           now,
        sched_last_seen:      None,
        nmi_last_seen:        None,
        dkom_suspect_since:   None,
        ghost_suspect_since:  None,
        tamper_suspect_since: None,
        silent_suspect_since: None,
        alerts: AlertState {
            last_dkom: None, last_ghost: None, last_tamper: None, last_silent: None,
        },
    });

    // NMI events don't carry start_time_ns (set to 0 in eBPF); only sched
    // events read group_leader->start_time and are authoritative for DUPE.
    if !is_nmi {
        if record.start_time_ns == 0 && info.start_time_ns != 0 {
            record.start_time_ns = info.start_time_ns;
        } else if info.start_time_ns != 0
               && record.start_time_ns != 0
               && record.start_time_ns != info.start_time_ns
        {
            println!("[DUPE]       tgid:{:<6} {:<16} task_struct spoofing suspected",
                info.tgid, resolve_comm(info.tgid));
        }
    }

    if is_nmi {
        record.nmi_last_seen = Some(now);
    } else {
        record.sched_last_seen = Some(now);
    }
}

fn run_detection(registry: &mut ProcessRegistry) {
    let user_tgids        = read_proc_tgids();
    let grace             = Duration::from_millis(GRACE_WINDOW_MS);
    let suspect_threshold = Duration::from_secs(SUSPECT_THRESHOLD_SECS);
    let ghost_threshold   = Duration::from_secs(GHOST_THRESHOLD_SECS);
    let cooldown          = Duration::from_secs(ALERT_COOLDOWN_SECS);
    let stale             = Duration::from_secs(10);
    let now               = Instant::now();

    for &tgid in &user_tgids {
        registry.entry(tgid).or_insert_with(|| ProcessRecord {
            start_time_ns:        0,
            first_seen:           now,
            sched_last_seen:      None,
            nmi_last_seen:        None,
            dkom_suspect_since:   None,
            ghost_suspect_since:  None,
            tamper_suspect_since: None,
            silent_suspect_since: None,
            alerts: AlertState {
                last_dkom: None, last_ghost: None, last_tamper: None, last_silent: None,
            },
        });
    }

    for (&tgid, record) in registry.iter_mut() {
        if record.first_seen.elapsed() < grace { continue; }

        let in_proc    = user_tgids.contains(&tgid);
        let ebpf_alive = record.sched_last_seen
            .map(|t| t.elapsed() < Duration::from_millis(500))
            .unwrap_or(false);
        let nmi_alive  = record.nmi_last_seen
            .map(|t| t.elapsed() < Duration::from_millis(1000))
            .unwrap_or(false);

        // [DKOM]: scheduled by kernel, absent from /proc.
        if !in_proc && (ebpf_alive || nmi_alive) {
            let since = record.dkom_suspect_since.get_or_insert(now);
            if since.elapsed() > suspect_threshold {
                let should_alert = record.alerts.last_dkom
                    .map(|t| t.elapsed() > cooldown).unwrap_or(true);
                if should_alert {
                    record.alerts.last_dkom = Some(now);
                    println!("[DKOM]       tgid:{:<6} {:<16} hidden {:.1}s",
                        tgid, resolve_comm(tgid), since.elapsed().as_secs_f64());
                }
            }
        } else {
            record.dkom_suspect_since = None;
            record.alerts.last_dkom   = None;
        }

        // [TAMPER]: NMI alive but sched_switch silent — tracepoint suppressed.
        if in_proc && nmi_alive && !ebpf_alive && record.sched_last_seen.is_some() {
            let since = record.tamper_suspect_since.get_or_insert(now);
            if since.elapsed() > suspect_threshold {
                let should_alert = record.alerts.last_tamper
                    .map(|t| t.elapsed() > cooldown).unwrap_or(true);
                if should_alert {
                    record.alerts.last_tamper = Some(now);
                    println!("[TAMPER]     tgid:{:<6} {:<16} NMI alive, tracepoint SILENT",
                        tgid, resolve_comm(tgid));
                }
            }
        } else {
            record.tamper_suspect_since = None;
            record.alerts.last_tamper   = None;
        }

        // [SILENT]: in /proc, both channels dead — total observation loss.
        if in_proc && !ebpf_alive && !nmi_alive
            && (record.sched_last_seen.is_some() || record.nmi_last_seen.is_some())
        {
            let since = record.silent_suspect_since.get_or_insert(now);
            if since.elapsed() > ghost_threshold {
                let should_alert = record.alerts.last_silent
                    .map(|t| t.elapsed() > cooldown).unwrap_or(true);
                if should_alert {
                    record.alerts.last_silent = Some(now);
                    println!("[SILENT]     tgid:{:<6} {:<16} total observation loss",
                        tgid, resolve_comm(tgid));
                }
            }
        } else {
            record.silent_suspect_since = None;
            record.alerts.last_silent   = None;
        }

        // [GHOST]: in /proc, never seen by any eBPF channel.
        if in_proc && record.sched_last_seen.is_none() && record.nmi_last_seen.is_none() {
            let since = record.ghost_suspect_since.get_or_insert(now);
            if since.elapsed() > ghost_threshold {
                let should_alert = record.alerts.last_ghost
                    .map(|t| t.elapsed() > cooldown).unwrap_or(true);
                if should_alert {
                    record.alerts.last_ghost = Some(now);
                    println!("[GHOST]      tgid:{:<6} {:<16} present in /proc, never seen by eBPF",
                        tgid, resolve_comm(tgid));
                }
            }
        } else {
            record.ghost_suspect_since = None;
            record.alerts.last_ghost   = None;
        }
    }

    registry.retain(|&tgid, record| {
        let sched_age = record.sched_last_seen.map(|t| t.elapsed()).unwrap_or(Duration::MAX);
        let nmi_age   = record.nmi_last_seen.map(|t| t.elapsed()).unwrap_or(Duration::MAX);
        (sched_age < stale && nmi_age < stale) || user_tgids.contains(&tgid)
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn deobfuscate(raw: &ProcessInfo, base_key: u64) -> ProcessInfo {
    let key = base_key;
    let mut info = *raw;

    info.pid ^= key as u32;
    info.tgid ^= (key >> 32) as u32;
    info.last_seen ^= key;
    info.start_time_ns ^= key;
    info.cpu ^= key as u32;

    let k_bytes = key.to_ne_bytes();
    for i in 0..8 {
        info.comm[i] ^= k_bytes[i];
        info.comm[i + 8] ^= k_bytes[i];
    }

    // event_type is never obfuscated; copy as-is.
    info
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

fn comm_str(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

fn resolve_comm(tgid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", tgid))
        .unwrap_or_else(|_| "???".into())
        .trim()
        .to_string()
}

fn verify_tpm_pcrs() {
    println!("[TPM]        Auditing Platform Configuration Registers (PCRs)...");
    let output = std::process::Command::new("tpm2_pcrread")
        .args(["sha256:0,2,4,7"])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            if let Ok(stdout) = String::from_utf8(out.stdout) {
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("0 :") || trimmed.starts_with("2 :") || trimmed.starts_with("4 :") || trimmed.starts_with("7 :")
                       || trimmed.contains(":") {
                        println!("[TPM]        {}", trimmed);
                    }
                }
                println!("[TPM]        PCR audit complete. Boot measurements recorded.");
            }
        }
        _ => {
            eprintln!("[WARN]       TPM PCR verification failed: tpm2_pcrread unavailable or returned error.");
            eprintln!("[WARN]       Cannot verify early boot chain integrity.");
        }
    }
}

fn read_tpm_key() -> Option<u64> {
    verify_tpm_pcrs();

    let output = std::process::Command::new("tpm2_getrandom")
        .args(["8", "--hex"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    // tpm2-tools 4.x+ prefixes output with "0x". The leading '0' is a valid hex
    // digit so filter(is_ascii_hexdigit) alone keeps it, producing a 17-char
    // string that overflows u64::from_str_radix. Strip the prefix first.
    let stripped = raw.trim().trim_start_matches("0x");
    let hex: String = stripped.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 16 {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

// ── Security stack pre-flight ─────────────────────────────────────────────────
//
// SPiCa is the last enforcement layer. It works best when the layers above it
// (Secure Boot → module signing → IMA) are also active. This function checks
// each layer and warns when one is missing — it does not implement any of them.

fn check_secure_boot() -> bool {
    let Ok(vars) = fs::read_dir("/sys/firmware/efi/efivars") else { return false };
    for entry in vars.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("SecureBoot-") {
            // EFI var layout: 4 bytes attributes + variable-length data.
            // For SecureBoot the data is a single u8: 1 = enabled.
            if let Ok(data) = fs::read(entry.path()) {
                return data.get(4).copied() == Some(1);
            }
        }
    }
    false
}

fn check_module_sig_force() -> bool {
    let uname = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let config = format!("/boot/config-{}", uname.trim());
    fs::read_to_string(&config)
        .map(|c| c.contains("CONFIG_MODULE_SIG_FORCE=y"))
        .unwrap_or(false)
}

fn check_ima_active() -> bool {
    std::path::Path::new("/sys/kernel/security/ima").exists()
}

fn check_ima_module_policy() -> bool {
    // /proc/cmdline is the most portable place to see whether an IMA module
    // appraise policy was requested at boot. The runtime policy file is
    // write-only on most distros so we cannot read it back.
    fs::read_to_string("/proc/cmdline")
        .map(|c| {
            c.contains("ima_policy=appraise_tcb")
                || c.contains("ima_appraise=enforce")
                || c.contains("ima_template=ima-sig")
        })
        .unwrap_or(false)
}

fn check_security_stack() {
    let secure_boot   = check_secure_boot();
    let mod_sig_force = check_module_sig_force();
    let ima_active    = check_ima_active();
    let ima_policy    = check_ima_module_policy();

    let ok  = |b: bool| if b { "OK      " } else { "MISSING " };
    println!("[STACK]      Secure Boot ............. {}", ok(secure_boot));
    println!("[STACK]      Module signing (SIG_FORCE) {}", ok(mod_sig_force));
    println!("[STACK]      IMA active ............... {}", ok(ima_active));
    println!("[STACK]      IMA module appraise policy {}", ok(ima_policy));

    let warn = !secure_boot || !mod_sig_force || !ima_active || !ima_policy;
    if warn {
        eprintln!("[WARN]       One or more security stack layers are missing.");
        eprintln!("[WARN]       SPiCa's BPF gate is a last-resort control, not a substitute.");
        eprintln!("[WARN]       See README: Defense in Depth for setup instructions.");
    }

    let lsm_available = fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.contains("bpf"))
        .unwrap_or(false);
    if !lsm_available {
        eprintln!("[CRITICAL]   BPF LSM GATEWAY IS DISABLED OR UNAVAILABLE!");
        eprintln!("[CRITICAL]   If you require dynamic LKM (Kernel Module) loading at runtime, SPiCa's eBPF");
        eprintln!("[CRITICAL]   telemetry CANNOT guarantee integrity. A hostile LKM possesses Ring 0 capability");
        eprintln!("[CRITICAL]   and can silently suppress or tamper with all eBPF hooks (sched_switch, NMI, etc.).");
        eprintln!("[CRITICAL]   SAFE ALTERNATIVE: To dynamically load modules securely at runtime, you must configure");
        eprintln!("[CRITICAL]   the native Linux Integrity Measurement Architecture (IMA) subsystem with");
        eprintln!("[CRITICAL]   signature-based appraisal policies (func=MODULE_CHECK appraise_type=imasig).");
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    if std::path::Path::new(WATCHDOG_PIN).exists() {
        println!("[WATCHDOG]   Previous SPiCa instance was not cleanly terminated — possible SIGKILL or crash");
        let _ = fs::remove_file(WATCHDOG_PIN);
    }

    check_security_stack();

    let base_key: u64 = match read_tpm_key() {
        Some(k) => { println!("[KEY]        TPM key loaded"); k }
        None    => { eprintln!("[KEY]        TPM unavailable — using compile-time key"); COMPILE_TIME_BASE_KEY }
    };

    // Derive integrity token from BASE_KEY via SipHash so that sc_canary[0]
    // (enumerable map, readable by root) does not reveal BASE_KEY.
    // Written to both .bss (INTEGRITY_TOKEN — authoritative) and sc_canary
    // (the named map the NMI compares against at runtime).
    let integrity_token: u64 = derive_integrity_token(base_key);

    let mut bpf = Bpf::load(include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/spica")
    ))?;

    // Write all .bss globals before any program is loaded into the kernel.
    // set_global() modifies the backing ELF section; the kernel receives the values
    // as part of the program load, not via an enumerable map update.
    bpf.set_global("BASE_KEY", base_key, false)?;
    bpf.set_global("SPICA_PID", std::process::id(), false)?;
    bpf.set_global("INTEGRITY_TOKEN", integrity_token, false)?;

    let btf = Btf::from_sys_fs()?;

    let sched_prog: &mut BtfTracePoint = bpf.program_mut("spica_sched").unwrap().try_into()?;
    sched_prog.load("sched_switch", &btf)?;
    sched_prog.attach()?;

    let lsm_available = fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.contains("bpf"))
        .unwrap_or(false);
    if lsm_available {
        let lsm_prog: &mut Lsm = bpf.program_mut("spica_lsm_modblock").unwrap().try_into()?;
        lsm_prog.load("kernel_read_file", &btf)?;
        lsm_prog.attach()?;
        // Lock immediately after attach — no reason to leave the window open
        // while canary, NMI, and watchdog pin are set up.
        let mut gate: Array<_, u32> = bpf.map_mut("sc_gate").unwrap().try_into()?;
        gate.set(0, 1u32, 0)?;
        println!("[LSM]        Module loading locked — no new LKMs permitted");
    } else {
        eprintln!("[LSM]        BPF LSM unavailable — kernel needs CONFIG_BPF_LSM + lsm=bpf; module blocking disabled");
    }

    let watchdog_prog: &mut TracePoint = bpf.program_mut("spica_watchdog").unwrap().try_into()?;
    watchdog_prog.load()?;
    watchdog_prog.attach("sched", "sched_process_exit")?;

    // Load and attach XDP program to block incoming traffic during initialization window
    let xdp_prog: &mut Xdp = bpf.program_mut("spica_xdp").unwrap().try_into()?;
    xdp_prog.load()?;
    
    let mut attached_ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let iface = entry.file_name().to_string_lossy().into_owned();
            if iface != "lo" {
                match xdp_prog.attach(&iface, XdpFlags::default()) {
                    Ok(_link) => {
                        attached_ifaces.push(iface);
                    }
                    Err(e) => {
                        eprintln!("[XDP]        Failed to attach packet drop to interface {}: {:?}", iface, e);
                    }
                }
            }
        }
    }
    if !attached_ifaces.is_empty() {
        println!("[XDP]        Early boot network blocking active on interfaces: {:?}", attached_ifaces);
    } else {
        println!("[XDP]        No active network interfaces attached for blocking.");
    }

    // Write the integrity canary BEFORE attaching the NMI program.
    // sc_canary exists as soon as Bpf::load() runs (maps are created then).
    // If we wrote it after nmi_prog.attach(), the NMI could fire in the gap
    // and see canary=0 vs INTEGRITY_TOKEN!=0 → spurious [TAMPER] on startup.
    {
        let mut canary_map: Array<_, u64> = bpf.map_mut("sc_canary").unwrap().try_into()?;
        canary_map.set(0, integrity_token, 0)?;
    }

    let nmi_prog: &mut PerfEvent = bpf.program_mut("spica_nmi").unwrap().try_into()?;
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

    // Pin the watchdog map to BPF-FS so it outlives a SIGKILL.
    bpf.map("sc_wd").unwrap().pin(WATCHDOG_PIN)?;

    let sched_rb = RingBuf::try_from(bpf.take_map("sc_sched").unwrap())?;
    let mut sched_fd = AsyncFd::new(sched_rb)?;

    let nmi_rb = RingBuf::try_from(bpf.take_map("sc_nmi").unwrap())?;
    let mut nmi_fd = AsyncFd::new(nmi_rb)?;

    let lsm_rb = RingBuf::try_from(bpf.take_map("sc_lsm").unwrap())?;
    let mut lsm_fd = AsyncFd::new(lsm_rb)?;

    let mut registry: ProcessRegistry = HashMap::new();

    let startup = Instant::now();
    for tgid in read_proc_tgids() {
        registry.insert(tgid, ProcessRecord {
            start_time_ns:        0,
            first_seen:           startup,
            sched_last_seen:      Some(startup),
            nmi_last_seen:        None,
            dkom_suspect_since:   None,
            ghost_suspect_since:  None,
            tamper_suspect_since: None,
            silent_suspect_since: None,
            alerts: AlertState {
                last_dkom: None, last_ghost: None, last_tamper: None, last_silent: None,
            },
        });
    }

    // Seeding process registry completed. Unlock network traffic!
    {
        let mut net_gate: Array<_, u32> = bpf.map_mut("sc_net_gate").unwrap().try_into()?;
        net_gate.set(0, 1u32, 0)?;
        println!("[XDP]        System initialized; network blocking disarmed.");
    }

    println!("I'm going to sing, so shine bright, SPiCa...");

    let mut tick = tokio::time::interval(Duration::from_millis(TICK_RATE_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sigterm = signal(SignalKind::terminate())?;

    loop {
        tokio::select! {
            guard = sched_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let raw = unsafe { &*(item.as_ptr() as *const ProcessInfo) };
                    // event_type is read before deobfuscation (it is never XOR'd).
                    if raw.event_type == 0 {
                        process_event(&deobfuscate(raw, base_key), &mut registry, false);
                    }
                }
                guard.clear_ready();
            }
            guard = nmi_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let raw = unsafe { &*(item.as_ptr() as *const ProcessInfo) };
                    if raw.event_type == 1 {
                        // NMI detected sc_canary mismatch: Singularity intercepted
                        // the bpf_map_update_elem call for the integrity canary.
                        println!("[TAMPER]     BPF map integrity check failed — sc_canary intercepted");
                    } else {
                        process_event(&deobfuscate(raw, base_key), &mut registry, true);
                    }
                }
                guard.clear_ready();
            }
            guard = lsm_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let ev = unsafe { &*(item.as_ptr() as *const LkmEvent) };
                    let comm = comm_str(&ev.comm);
                    if ev.allowed == 1 {
                        println!("[LKM-ALLOW]  tgid:{:<6} {:<16} module loaded (boot window, gate open)",
                            ev.tgid, comm);
                    } else {
                        println!("[LKM-DENY]   tgid:{:<6} {:<16} module load blocked (gate locked)",
                            ev.tgid, comm);
                    }
                }
                guard.clear_ready();
            }
            _ = tick.tick() => {
                run_detection(&mut registry);
            }
            _ = sigterm.recv() => { break; }
            _ = tokio::signal::ctrl_c() => { break; }
        }
    }

    println!("Catch me! I'll leap over Denebola");
    let _ = fs::remove_file(WATCHDOG_PIN);

    Ok(())
}

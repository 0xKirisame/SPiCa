mod bpf;
mod proc;

use bpf::BpfRuntime;
use clap::{Parser, Subcommand};
use spica_common::{LedgerRecord, LkmEvent, NotaryEvent, KIND_SWITCH};
use spica_detect::{ChainTracker, Detection, DetectionClass, ProcessRecord, ProcessRegistry};
use std::fs;
use std::time::{Duration, Instant};
use tokio::signal::unix::{signal, SignalKind};

const TICK_RATE_MS: u64 = 100;
/// PCR anchor cadence: the daemon extends PCR16 with a commitment to its
/// verified chain heads every N seconds. Short enough that a suppression
/// window is bounded, long enough to keep TPM traffic trivial (~ms ops).
const PCR_EPOCH_SECS: u64 = 10;

#[derive(Parser)]
#[command(version, about = "SPiCa — System Process Integrity & Cross-view Analysis")]
struct Cli {
    /// Subcommand. If omitted, SPiCa runs detection (default behavior).
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Install SPiCa to /usr/local/bin and integrate with initramfs (requires root).
    /// Auto-detects Debian (initramfs-tools) or Fedora (dracut).
    Install,

    /// Remove SPiCa and its initramfs integration (requires root).
    /// While the bpf() gate is armed, this requires the one-time token
    /// printed at launch (--token <64-hex-chars>). Rebuilds the initramfs
    /// so the next boot doesn't reference removed hooks.
    Uninstall {
        /// The one-time uninstall token (64 hex chars) printed at launch.
        /// Required whenever the bpf() gate is armed; without it, removal
        /// requires a reboot.
        #[arg(long, value_parser = parse_token)]
        token: Option<[u8; 32]>,
    },

    /// Seal this installation to the TPM (requires a TPM and root).
    /// Defines a policy-protected NV secret bound to the SPiCa binary hash
    /// (PCR17) and the measured boot chain (PCR4/9 when available). After
    /// sealing, the daemon refuses to start unless the initramfs genesis
    /// step succeeded — a tampered kernel, initramfs, or binary means no
    /// secret, no start, no silent fiction.
    SealInstall,

    /// Initramfs-stage entry: measure this binary into PCR17 and unseal the
    /// secret under the current PCR policy. Called by the initramfs hook
    /// before the daemon starts.
    Genesis {
        /// Where to drop the unsealed secret (tmpfs, mode 0600).
        #[arg(long, default_value = "/run/spica.genesis")]
        out: std::path::PathBuf,
        /// Install record for the cross-check.
        #[arg(long, default_value = "/etc/spica/genesis.expected")]
        expected: std::path::PathBuf,
    },
}

fn parse_token(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(s).ok_or("expected 64 hex characters")?;
    bytes.try_into().map_err(|_| "expected 64 hex characters".to_string())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() != 64 {
        return None;
    }
    (0..32)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Install) => return spica_install::install().map_err(Into::into),
        Some(Command::Uninstall { token }) => {
            return uninstall(token).map_err(Into::into);
        }
        Some(Command::SealInstall) => {
            match spica_key::seal::install() {
                Ok(msg) => {
                    println!("[SEAL]       {msg}");
                }
                Err(why) => return Err(anyhow::anyhow!("seal-install failed: {why}")),
            }
            return Ok(());
        }
        Some(Command::Genesis { out, expected }) => match spica_key::seal::genesis(&out, &expected) {
            Ok(()) => {
                println!("[SEAL]       genesis: binary measured, secret unsealed to {}", out.display());
            }
            Err(why) => {
                eprintln!("[SEAL]       GENESIS FAILED: {why}");
                eprintln!("[SEAL]       tampered boot/kernel/binary, or missing TPM — SPiCa will refuse to anchor");
                std::process::exit(1);
            }
        },
        None => {} // fall through to normal detection run
    }
    // The detection loop is async — hand off to a tokio runtime.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_detection())
}

/// Authorized removal: knock on the bpf() gate with the one-time token,
/// stop any running instance, detach everything by unlinking the pins, then
/// run the filesystem uninstall. If the gate rejects (or no token was
/// given), abort loudly — on a gated machine, removal-by-reboot is the
/// correct incident-response path, not a bug.
fn uninstall(token: Option<[u8; 32]>) -> Result<(), anyhow::Error> {
    if let Some(t) = &token {
        match bpf::knock(t) {
            Ok(()) => println!("[UNINSTALL]   knock accepted — 60s authorization window open"),
            Err(why) => {
                return Err(anyhow::anyhow!(
                    "refusing to uninstall: {why}. Reboot and disable the launcher if the token is lost."
                ));
            }
        }
    } else if bpf::watchdog_pin_exists() {
        eprintln!("[UNINSTALL]   WARNING: no token given and SPiCa artifacts exist — if the bpf() gate is armed, this cannot fully remove them.");
    }

    // Stop a running instance (SIGTERM → its clean-shutdown path unpins).
    // NOTE: pkill -x spica would match THIS process too (same binary name) —
    // scan /proc and skip self.
    let me = std::process::id();
    let proc_dir = fs::read_dir("/proc").unwrap_or_else(|_| fs::read_dir(".").unwrap());
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) else {
            continue;
        };
        if comm.trim() == "spica" {
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            println!("[UNINSTALL]   running instance {pid} stopped");
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Detach everything that survived (pinned links, watchdog map).
    bpf::remove_link_pins();
    bpf::clear_watchdog_pin();
    println!("[UNINSTALL]   links detached, pins removed");

    spica_install::uninstall().map_err(Into::into)
}

async fn run_detection() -> Result<(), anyhow::Error> {
    // 1. Watchdog — check for leftover pin from a previously-killed instance.
    if bpf::watchdog_pin_exists() {
        println!("[WATCHDOG]   Previous SPiCa instance was not cleanly terminated — possible SIGKILL or crash");
        bpf::clear_watchdog_pin();
    }

    // 2. Security stack audit (Secure Boot / module signing / IMA / BPF LSM).
    spica_seccheck::run();

    // 3. One-time uninstall token + eBPF load. Inside load(): link pins are
    //    reaped from any SIGKILLed predecessor, programs attach AND PIN
    //    (attachments survive SIGKILL), the LKM gate closes and freezes,
    //    chain state (.bss incl. AUTH_TOKEN / ledger / watchdog) freezes,
    //    and the deny-by-default bpf() gate attaches last. Any freeze
    //    failure aborts here — fail-closed, never run on spoofable state.
    let mut auth_token = [0u8; 32];
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(&mut auth_token)?;
    }
    println!("[TOKEN]      ╔══════════════════════════════════════════════════╗");
    println!("[TOKEN]      ║  ONE-TIME UNINSTALL TOKEN — RECORD IT NOW          ║");
    println!("[TOKEN]      ║  {}", hex(&auth_token));
    println!("[TOKEN]      ║  Lost token + armed gate = removal by reboot.      ║");
    println!("[TOKEN]      ╚══════════════════════════════════════════════════╝");

    // 3b. SEALED-INSTALLATION GATE — BEFORE any kernel state is armed.
    //     The initramfs `spica genesis` step measured this binary and unsealed
    //     the secret only if boot/kernel/binary matched the sealed policy.
    //     Verifying FIRST means a refusal leaves no gates, no pins, no
    //     armed anything behind (an armed-but-dead SPiCa would deny bpf()
    //     to the whole system — found live when systemd wedged).
    let sealed_installed = std::path::Path::new(spica_key::seal::EXPECTED_GENESIS_PATH).exists();
    let genesis_secret: Option<[u8; 32]> = if sealed_installed {
        match fs::read(spica_key::seal::GENESIS_OUT_PATH)
            .map_err(|e| e.to_string())
            .and_then(|v| v.try_into().map_err(|_| "bad secret size".to_string()))
        {
            Ok(secret) => {
                let expected = fs::read_to_string(spica_key::seal::EXPECTED_GENESIS_PATH)
                    .unwrap_or_default();
                let got_hex: String = spica_common::genesis_digest(&secret)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                if got_hex != expected.trim() {
                    return Err(anyhow::anyhow!(
                        "genesis secret does not match the install record — refusing to run \
                         (tampered seal record or secret)"
                    ));
                }
                Some(secret)
            }
            Err(why) => {
                return Err(anyhow::anyhow!(
                    "sealed installation but no genesis secret ({why}) — tampered \
                     boot/kernel/binary or the initramfs hook is missing; refusing to run"
                ));
            }
        }
    } else {
        None
    };

    let mut rt = BpfRuntime::load(std::process::id(), auth_token)?;
    let st = rt.status();
    if st.modblock {
        println!("[LSM]        Module loading locked — no new LKMs permitted");
    } else {
        eprintln!("[LSM]        BPF LSM unavailable — kernel needs CONFIG_BPF_LSM + lsm=bpf; module blocking disabled");
    }
    if st.bpfgate {
        println!("[LSM]        bpf() syscall gate armed — non-SPiCa processes cannot load or acquire BPF objects");
    }
    if st.nmi_hw {
        println!("[NMI]        notary on hardware PMU (NMI context)");
    } else {
        eprintln!("[NMI]        WARNING: no hardware PMU — notary on software events; chain cross-checks intact, NMI hardening absent (degraded)");
    }

    // 4. Seed the process registry from /proc. Treat every currently-visible
    //    process as "observed at startup" so they don't trip GHOST.
    let mut registry: ProcessRegistry = Default::default();
    let startup = Instant::now();
    for tgid in proc::read_tgids() {
        registry.insert(tgid, ProcessRecord::seeded(0));
    }

    // Time helper: nanos since startup, floored to 1 to avoid colliding with
    // the "never seen" sentinel (0) used inside spica-detect.
    let nanos_since_startup = || {
        let n = Instant::now().duration_since(startup).as_nanos() as u64;
        n.max(1)
    };

    println!("I'm going to sing, so shine bright, SPiCa...");

    // 6. TPM PCR anchor — out-of-band finality. Each epoch extends PCR16
    //    with a commitment to the verified chain heads; a local mirror of
    //    the PCR (extend = SHA256(old||value)) is compared against the live
    //    PCR every epoch, turning garbage-extension into [PCR-DIVERGE].
    //    Sealed installs bind the first extend (genesis) to the unsealed
    //    secret — the chain's history starts only on a measured boot.
    //    No TPM (VMs without vTPM, non-Linux) → loud degraded banner
    //    (unsealed mode only; sealed installs refuse above).
    let mut pcr = match spica_key::pcr::PcrAnchor::open() {
        Ok(mut anchor) => {
            match (&genesis_secret, anchor.genesis_pending()) {
                (Some(secret), true) => match anchor.genesis(secret) {
                    Ok(mirror) => println!(
                        "[PCR]        genesis bound to sealed boot — pcr16={}",
                        mirror.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    ),
                    Err(why) => {
                        return Err(anyhow::anyhow!("genesis extend failed: {why}"));
                    }
                },
                (Some(_), false) => {
                    eprintln!("[PCR]        NOTE: resuming within-boot — genesis already bound");
                }
                (None, _) => println!(
                    "[PCR]        anchor armed on PCR{} — ledger heads committed every {PCR_EPOCH_SECS}s (unsealed mode)",
                    spica_common::PCR_INDEX
                ),
            }
            Some(anchor)
        }
        Err(why) => {
            eprintln!("[PCR]        WARNING: anchor unavailable ({why}); ledger integrity is in-band only — a full userspace MITM is undetectable without out-of-band attestation");
            None
        }
    };

    // 7. Event loop. Ring buffer polling lives here (tokio::select! needs
    //    direct AsyncFd guard access); detection logic lives in spica-detect.
    let mut alerts: Vec<Detection> = Vec::new();
    let mut channel_cd = spica_detect::ChannelCooldown::default();
    let mut chain = ChainTracker::default();
    let mut last_nmi_hb: u64 = 0;
    let mut pid_tgid_cache: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    let mut tick_count: u64 = 0;
    let mut tick = tokio::time::interval(Duration::from_millis(TICK_RATE_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pcr_tick = tokio::time::interval(Duration::from_secs(PCR_EPOCH_SECS));
    pcr_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pcr_fail_streak: u32 = 0;
    let mut sigterm = signal(SignalKind::terminate())?;

    loop {
        let (sched_rb, nmi_rb, lsm_rb) = rt.split_ring_buffers();
        tokio::select! {
            guard = sched_rb.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let rec = unsafe { &*(item.as_ptr() as *const LedgerRecord) };
                    let rec = *rec;
                    // SWITCH records carry the thread ID (next_pid), not the
                    // TGID. Resolve via /proc/<pid>/status with a cache — but
                    // NEVER write it back into the record: the chain hash
                    // covers tgid, and mutating before verification desyncs
                    // the chain (found in the first VM run).
                    let resolved_tgid = if rec.kind == KIND_SWITCH && rec.tgid != 0 {
                        Some(if let Some(&t) = pid_tgid_cache.get(&rec.pid) {
                            t
                        } else {
                            let t = proc::resolve_tgid(rec.pid).unwrap_or(rec.pid);
                            pid_tgid_cache.insert(rec.pid, t);
                            t
                        })
                    } else {
                        None
                    };
                    if let Some(d) = spica_detect::on_ledger_event(
                        rec, resolved_tgid, &mut chain, &mut registry, nanos_since_startup(),
                    ) {
                        print_detection(&d);
                    }
                }
                guard.clear_ready();
            }
            guard = nmi_rb.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let ev = unsafe { &*(item.as_ptr() as *const NotaryEvent) };
                    // Every notary event proves the NMI channel is alive.
                    last_nmi_hb = nanos_since_startup();
                    // Cross-check the snapshot against the running chain:
                    // ahead = suppressed records, mismatch = edited records.
                    if let Some(d) = spica_detect::on_notary_event(
                        *ev, &mut chain, nanos_since_startup(),
                    ) {
                        print_detection(&d);
                    }
                }
                guard.clear_ready();
            }
            guard = lsm_rb.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let ev = unsafe { &*(item.as_ptr() as *const LkmEvent) };
                    let d = spica_detect::on_lkm_event(*ev);
                    print_detection(&d);
                }
                guard.clear_ready();
            }
            _ = tick.tick() => {
                let proc_tgids = proc::read_tgids();
                let proc_tgids_libc = proc::read_tgids_libc();
                let now = nanos_since_startup();
                // Periodically clear the PID→TGID cache to reclaim memory
                // from exited threads and handle PID recycling.
                tick_count += 1;
                if tick_count % 300 == 0 {
                    pid_tgid_cache.clear();
                }
                spica_detect::evaluate(
                    &mut registry, &proc_tgids, &proc_tgids_libc, now, last_nmi_hb,
                    &mut channel_cd, &mut alerts,
                );
                for d in &alerts {
                    print_detection(d);
                }
            }
            _ = pcr_tick.tick() => {
                let Some(anchor) = pcr.as_mut() else { continue };
                let snapshot = chain.snapshot();
                match anchor.tick(&snapshot) {
                    spica_key::pcr::TickOutcome::Extended { epoch, mirror } => {
                        pcr_fail_streak = 0;
                        // One line per minute keeps the log auditable without
                        // drowning it; the digest printed is the expected PCR
                        // value — an offline quote must reproduce it.
                        if epoch % (60 / PCR_EPOCH_SECS) == 0 {
                            println!("[PCR]        epoch {epoch} anchored, pcr16={}", hex(&mirror));
                        }
                    }
                    spica_key::pcr::TickOutcome::Diverged { epoch, mirror, tpm } => {
                        pcr_fail_streak = 0;
                        print_detection(&Detection {
                            class: DetectionClass::PcrDiverge,
                            tgid: 0,
                            elapsed: 0,
                            details: format!(
                                "TPM PCR{} diverged at epoch {epoch}: expected {}, TPM reports {} — someone else extended the PCR (garbage-extension DoS or second extender)",
                                spica_common::PCR_INDEX,
                                hex(&mirror),
                                hex(&tpm),
                            ),
                        });
                    }
                    spica_key::pcr::TickOutcome::Failed { epoch } => {
                        pcr_fail_streak += 1;
                        if pcr_fail_streak == 6 {
                            eprintln!("[PCR]        WARNING: {pcr_fail_streak} consecutive extend failures at epoch {epoch} — TPM unhealthy or gone; anchoring degraded");
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    spica_key::pcr::TickOutcome::Unavailable => {}
                }
            }
            _ = sigterm.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    println!("Catch me! I'll leap over Denebola");
    // Clean operator shutdown: unpin links (detach) + drop the watchdog.
    bpf::remove_link_pins();
    bpf::clear_watchdog_pin();

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn print_detection(d: &Detection) {
    // LKM events fold the calling process's comm into the details string at
    // the source (on_lkm_event in spica-detect) because /proc/<tgid>/comm
    // can't be reliably read after the fact — insmod/modprobe often exit
    // before we print. Skip the comm column for those classes.
    match d.class {
        DetectionClass::LkmAllow | DetectionClass::LkmDeny | DetectionClass::Hook
        | DetectionClass::Inject | DetectionClass::PcrDiverge => {
            println!("[{:<10}] tgid:{:<6} {}",
                d.class.label(), d.tgid, d.details);
        }
        _ => {
            let comm = resolve_comm(d.tgid);
            println!("[{:<10}] tgid:{:<6} {:<16} {}",
                d.class.label(), d.tgid, comm, d.details);
        }
    }
}

fn resolve_comm(tgid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", tgid))
        .unwrap_or_else(|_| "???".into())
        .trim()
        .to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

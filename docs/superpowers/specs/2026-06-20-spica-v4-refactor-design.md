# SPiCa v4 Refactor — Design Spec

**Date:** 2026-06-20
**Status:** Approved via brainstorming session
**Scope:** Holistic refactor — code structure, TPM, XDP removal, threat-model rewrite, obfuscation review, plus self-installing initramfs integration

---

## 1. Goals

1. **Cleaner module separation** — split the 602-line `spica/src/main.rs` into focused modules with single responsibilities.
2. **Honest threat model** — README claims must match code behavior. Remove overclaims (Rice's theorem, TPM attestation, XOR-as-crypto) and replace with defensible, accurate labels.
3. **Drop XDP** — the all-interfaces traffic-block during init is a self-DoS risk; the LSM gate already covers the LKM threat vector.
4. **TPM via crate** — replace subprocess shelling (`tpm2_getrandom`/`tpm2_pcrread`) with `tss-esapi` for direct library calls. No subprocess command line visible to other processes, no pipe transit, no string parsing.
5. **Testable surface** — pure logic (detection FSM, key derivation, obfuscation, security-check parsing) isolated from I/O so it runs on Mac dev machines.
6. **Performance/regressions** — `ProcessRecord` reduced from ~264 bytes to 96 bytes via array-indexed class state and `u64` nanos instead of `Instant`.
7. **Self-installing initramfs integration** — `spica install` / `spica uninstall` subcommands auto-detect distro (Debian/Fedora), copy the binary, install hooks, rebuild initramfs. Replaces the three loose shell scripts in `spica/src/` that operators had to manually place. See §21.

## 2. Non-goals

- Real PCR-bound key sealing (roadmapped, not in this refactor)
- SipHash PRF obfuscation upgrade (kept XOR after analysis — see §8)
- eBPF verifier testing on Mac (impossible — only `cargo check` against `bpfel-unknown-none`)
- CI pipeline for Linux smoke tests (follow-up)
- Behavior changes to detection thresholds or alert semantics

## 3. Decisions locked in

| Decision | Choice | Rationale |
|---|---|---|
| Refactor approach | A (module-first decomposition) + good bits from C (`DetectionClass` enum, proper FSM) | Cleanest end state at this codebase scale (990 LOC) |
| TPM failure mode | Silent fallback, but visibly loud (`INSECURE MODE` banner) | Operator-visible degradation, no opt-in flag friction |
| XDP | Remove entirely | Self-DoS risk outweighs C2-block benefit; LSM gate covers LKM vector |
| TPM access | `tss-esapi` crate | Mature, used by Keylime, less code to maintain than raw ioctl |
| Obfuscation cipher | Keep XOR | Threat model doesn't justify 0.2% CPU for SipHash — known-plaintext attack requires ring buffer access the constrained adversary lacks |
| README | Restructure + tighten (~580 → ~290 lines) | Honest claims, narrative voice preserved where it earns space |
| PCR audit | Remove entirely | Current code is theater (prints without comparison); real PCR-bound sealing is a roadmap item |
| Process record layout | Array-indexed class state + `u64` nanos | 3.5× smaller per record, better cache locality, niche-friendly |
| Attribution | "Claude Code" → "GLM" in README disclaimer | Accurate to current tooling |
| Initramfs integration UX | `spica install` / `spica uninstall` subcommands | Replaces three loose shell scripts operators had to manually place; auto-detects distro |
| Distro support scope | Debian (initramfs-tools) + Fedora (dracut) only | Covers ~90% of Linux servers/desktops; mkinitcpio/SUSE are roadmap |
| Install subcommand shape | Install + uninstall (no `status`) | Minimum viable ops surface; status can come later if needed |

---

## 4. Module map

```
spica-common/src/
  lib.rs                 Shared types + obfuscation. no_std.
                         Used by both eBPF and userspace.
                         Contains: ProcessInfo, LkmEvent, xor_fields().
                         ~95 LOC.

spica-ebpf/src/
  main.rs                eBPF programs only. XDP removed.
                         Imports xor_fields from spica-common.
                         4 programs: spica_sched, spica_nmi,
                         spica_lsm_modblock, spica_watchdog.
                         ~320 LOC (was 350).

spica/src/
  main.rs                Entry, signal loop, orchestration only.
                         No business logic.
                         ~80 LOC (was 602).

  bpf.rs                 BpfRuntime struct: load(), set_global x3,
                         attach 4 programs, pin watchdog, lock gate.
                         Ring buffer poll methods.
                         ~150 LOC.

  key.rs                 KeySource trait + TpmKeySource (tss-esapi)
                         + CompileTimeKey fallback + StaticKey (test).
                         resolve() -> (u64, KeyOrigin).
                         derive_integrity_token() — SipHash-1-3 MAC
                         for the integrity canary.
                         ~80 LOC.

  detect.rs              DetectionClass enum, ProcessClass enum (storage index),
                         ProcessRecord, ClassState, Detection struct.
                         Pure functions: on_sched_event, on_nmi_event,
                         on_lkm_event, evaluate().
                         No I/O, no printing.
                         ~200 LOC.

  seccheck.rs            check_secure_boot, check_module_sig_force,
                         check_ima_active, check_ima_module_policy.
                         Parsing split from fs reads for testability.
                         ~70 LOC.

  proc.rs                read_tgids() behind a function boundary
                         (kept simple, not trait-abstracted — see §11).
                         ~30 LOC.

  install.rs             `spica install` / `spica uninstall` subcommands.
                         Detects distro (Debian initramfs-tools vs Fedora dracut),
                         copies binary to /usr/local/bin/spica, installs the
                         appropriate initramfs hooks via include_str!-embedded
                         scripts, rebuilds initramfs. See §21.
                         ~180 LOC.

  resources/             Shell scripts embedded via include_str! at compile time:
    debian-hook.sh         initramfs-tools hook (copies binary + libtss2-* libs)
    debian-script.sh       initramfs-tools init-premount script (mounts fs, starts spica)
    dracut-module-setup.sh dracut module-setup.sh
    dracut-init.sh         dracut pre-mount hook script
                         Replaces the current loose files in spica/src/.
```

**Total production LOC:** ~1140 (was 990; +180 for `install.rs`, ~60 for embedded scripts). The install feature adds real new capability, not just refactor churn.

---

## 5. Type system

```rust
// detect.rs

/// All detection classes — the public emission type.
/// Used in Detection.class for both tick-driven and event-driven alerts.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionClass {
    Dkom,        // scheduled by kernel, absent from /proc
    Ghost,       // in /proc, never observed by eBPF
    Tamper,      // NMI alive, sched silent (tracepoint suppression)
    Silent,      // both channels dead (total observation loss)
    Dupe,        // same TGID, different start_time_ns
    LkmAllow,    // boot-window module load
    LkmDeny,     // post-gate module load attempt
    Watchdog,    // prior instance killed ungracefully
}

/// Internal storage index for per-tick classes that need suspect-since +
/// cooldown state. Distinct from DetectionClass because event-driven
/// classes (Dupe, LkmAllow, LkmDeny, Watchdog) fire once and don't need
/// per-record storage.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessClass {
    Dkom = 0,
    Ghost = 1,
    Tamper = 2,
    Silent = 3,
}

impl ProcessClass {
    pub fn to_detection_class(self) -> DetectionClass {
        match self {
            ProcessClass::Dkom   => DetectionClass::Dkom,
            ProcessClass::Ghost  => DetectionClass::Ghost,
            ProcessClass::Tamper => DetectionClass::Tamper,
            ProcessClass::Silent => DetectionClass::Silent,
        }
    }

    pub const COUNT: usize = 4;
}

pub struct ClassState {
    pub suspect_since: u64,   // 8 bytes — nanos since process epoch; 0 = not suspect
    pub last_emitted:   u64,   // 8 bytes — nanos since process epoch; 0 = never emitted
}
// 16 bytes per ClassState

pub struct ProcessRecord {
    pub start_time_ns: u64,                          // 8  (kernel task birth time)
    pub first_seen:    u64,                          // 8  (nanos since process epoch)
    pub sched_last:    u64,                          // 8  (nanos since epoch; 0 = never)
    pub nmi_last:      u64,                          // 8  (nanos since epoch; 0 = never)
    pub classes:       [ClassState; ProcessClass::COUNT],  // 64 (4 × 16)
}
// 96 bytes total per record

impl ProcessRecord {
    /// Used by on_sched_event when a new tgid is observed.
    pub fn new(start_time_ns: u64, now_nanos: u64) -> Self {
        Self {
            start_time_ns,
            first_seen: now_nanos,
            sched_last: 0,
            nmi_last: 0,
            classes: [ClassState { suspect_since: 0, last_emitted: 0 };
                ProcessClass::COUNT],
        }
    }

    /// Used by main.rs when seeding the registry from /proc at startup.
    /// sched_last is set to `now_nanos` so the seeded process doesn't
    /// immediately trigger GHOST (it was "seen" at startup).
    pub fn seeded(now_nanos: u64) -> Self {
        Self {
            start_time_ns: 0,
            first_seen: now_nanos,
            sched_last: now_nanos,
            nmi_last: 0,
            classes: [ClassState { suspect_since: 0, last_emitted: 0 };
                ProcessClass::COUNT],
        }
    }
}

// Lock the layout — catches accidental padding regressions.
const _: () = assert!(std::mem::size_of::<ProcessRecord>() == 96);
const _: () = assert!(std::mem::size_of::<ClassState>() == 16);
```

### Time representation

`u64` nanoseconds from a process-local epoch (Instant captured at startup), not `std::time::Instant` directly.

**Why:** `Instant` is 16-24 bytes (Linux `timespec`) with no niche for `Option` optimization. `u64` fits 584 years of nanoseconds, monotonic via `Instant::duration_since(startup).as_nanos() as u64`, niche-friendly for sentinels (`0` = never).

**Conversion boundary:** Once per tick at the entry to `evaluate()`. Event handlers receive `u64` directly.

### Why not HashMap for class state?

Originally proposed `HashMap<DetectionClass, ClassState>` per record. Rejected because:
- Empty map header: 48 bytes
- Per-entry overhead: ~40 bytes (hash + key + padding)
- Per-tick hashing + cache misses (state scattered on heap)
- Per-record cost: ~340 bytes vs 96 with array

Array-indexed access via `class as usize` is cache-resident inside the record, zero allocation, no hashing.

### ProcessRegistry

```rust
pub type ProcessRegistry = std::collections::HashMap<u32, ProcessRecord>;
```

Unchanged from current. Keyed by TGID. Record size drops 3.5×, registry capacity at fixed memory increases proportionally.

### Memory footprint at scale

| Workload | Processes | Registry size (current) | Registry size (refactored) |
|---|---|---|---|
| Embedded / IoT | 50 | 13 KB | **5 KB** |
| Desktop | 200 | 53 KB | **19 KB** |
| Server | 2000 | 528 KB | **192 KB** |

---

## 6. Detection FSM

### Contract

```rust
// detect.rs

pub struct Detection {
    pub class: DetectionClass,
    pub tgid: u32,
    pub elapsed: u64,        // nanos the suspicious condition has held
    pub details: String,     // human-readable context for the alert line
}

/// Pure function. No I/O, no printing, no side effects on disk/stdout.
/// Caller owns `out` and reuses it across ticks (no per-tick allocation).
pub fn evaluate(
    registry: &mut ProcessRegistry,
    proc_tgids: &HashSet<u32>,
    now: u64,                        // nanos since process epoch
    out: &mut Vec<Detection>,
) {
    out.clear();
    // 1. Seed records for any /proc tgid not yet known (GHOST precondition)
    // 2. For each record past the grace window, run the 4 ProcessClass predicates
    // 3. Per-class suspect-since tracking, threshold check, cooldown check
    // 4. Append firing detections to `out`
    // 5. Eviction: registry.retain() removing records stale beyond STALE
}

/// Event handlers — also pure. Return Option<Detection> for event-driven classes.
pub fn on_sched_event(info: ProcessInfo, registry: &mut ProcessRegistry) -> Option<Detection> { /* DUPE check */ }
pub fn on_nmi_event(outcome: NmiOutcome, registry: &mut ProcessRegistry) -> Option<Detection> { /* TAMPER canary mismatch */ }
pub fn on_lkm_event(ev: LkmEvent) -> Detection { /* always emits LkmAllow or LkmDeny */ }
```

### Constants

```rust
const TICK_RATE_MS:           u64 = 100;
const SUSPECT_THRESHOLD_NANOS: u64 = 2_000_000_000;     // 2 sec
const GHOST_THRESHOLD_NANOS:   u64 = 5_000_000_000;     // 5 sec
const ALERT_COOLDOWN_NANOS:    u64 = 30_000_000_000;    // 30 sec
const GRACE_WINDOW_NANOS:      u64 = 50_000_000;        // 50 ms
const STALE_NANOS:             u64 = 10_000_000_000;     // 10 sec
const SCHED_LIVENESS_NANOS:    u64 =    500_000_000;    // 500 ms
const NMI_LIVENESS_NANOS:      u64 =  1_000_000_000;    // 1 sec
```

All values preserved from current implementation. No semantic change.

### Predicates as data

The 4 `ProcessClass` predicates share a uniform loop body — only the predicate function and threshold differ. Implementation pattern:

```rust
// Pseudocode for the per-record evaluation
let in_proc    = proc_tgids.contains(&tgid);
let sched_live = sched_last != 0 && now - sched_last < SCHED_LIVENESS_NANOS;
let nmi_live   = nmi_last   != 0 && now - nmi_last   < NMI_LIVENESS_NANOS;

// DKOM:   !in_proc && (sched_live || nmi_live)
// TAMPER:  in_proc && nmi_live && !sched_live && sched_last != 0
// SILENT:  in_proc && !sched_live && !nmi_live && (sched_last != 0 || nmi_last != 0)
// GHOST:   in_proc && sched_last == 0 && nmi_last == 0

for class in [ProcessClass::Dkom, ProcessClass::Tamper, ProcessClass::Silent, ProcessClass::Ghost] {
    let predicate = match class { /* per-class predicate */ };
    let threshold = match class { /* per-class threshold */ };
    let cs = &mut record.classes[class as usize];
    if predicate {
        if cs.suspect_since == 0 { cs.suspect_since = now; }
        if now - cs.suspect_since > threshold {
            let should_emit = cs.last_emitted == 0 || now - cs.last_emitted > ALERT_COOLDOWN_NANOS;
            if should_emit {
                cs.last_emitted = now;
                out.push(Detection {
                    class: class.to_detection_class(),
                    tgid,
                    elapsed: now - cs.suspect_since,
                    details: /* per-class human-readable context */,
                });
            }
        }
    } else {
        cs.suspect_since = 0;
        cs.last_emitted = 0;
    }
}
```

### DUPE handling (event-driven)

DUPE is checked in `on_sched_event` (not `evaluate`) because it triggers on a `start_time_ns` mismatch at arrival, not on a tick boundary:

```rust
pub fn on_sched_event(info: ProcessInfo, registry: &mut ProcessRegistry) -> Option<Detection> {
    let now = nanos_since_startup();
    let rec = registry.entry(info.tgid)
        .or_insert_with(|| ProcessRecord::new(info.start_time_ns, now));
    if rec.start_time_ns != 0 && info.start_time_ns != 0 && rec.start_time_ns != info.start_time_ns {
        return Some(Detection {
            class: DetectionClass::Dupe,
            tgid: info.tgid,
            elapsed: 0,
            details: format!("task_struct spoofing suspected"),
        });
    }
    if rec.start_time_ns == 0 { rec.start_time_ns = info.start_time_ns; }
    rec.sched_last = info.last_seen;
    None
}
```

### Alert emission (caller responsibility)

`evaluate()` and the `on_*_event` functions return `Detection` values. `main.rs` handles formatting and printing:

```rust
for d in &alerts {
    println!("[{:<10}] tgid:{:<6} {:<16} {}",
        format!("{:?}", d.class).to_uppercase(),
        d.tgid, resolve_comm(d.tgid), d.details);
}
```

Detection logic never touches stdout.

---

## 7. Key management

### KeySource trait

```rust
// key.rs

pub trait KeySource {
    fn get_random_key(&mut self) -> Result<u64, KeyError>;
}

pub enum KeyError {
    TpmUnavailable,
    TpmCommandFailed(String),
}

pub enum KeyOrigin { Tpm, CompileTime }
```

### TpmKeySource (production)

```rust
pub struct TpmKeySource { ctx: tss_esapi::Context }

impl TpmKeySource {
    pub fn new() -> Result<Self, KeyError> {
        let ctx = tss_esapi::Context::new(
                tss_esapi::tcti_ldr::TctiNamePts::Device())
            .map_err(|_| KeyError::TpmUnavailable)?;
        Ok(Self { ctx })
    }
}

impl KeySource for TpmKeySource {
    fn get_random_key(&mut self) -> Result<u64, KeyError> {
        let bytes = self.ctx.get_random(8)
            .map_err(|e| KeyError::TpmCommandFailed(e.to_string()))?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(u64::from_ne_bytes(arr))
    }
}
```

No subprocess. No `/proc/<pid>/cmdline` leak. No pipe transit. No string parsing.

### CompileTimeKey fallback

```rust
pub struct CompileTimeKey;
impl KeySource for CompileTimeKey {
    fn get_random_key(&mut self) -> Result<u64, KeyError> {
        Ok(COMPILE_TIME_BASE_KEY)
    }
}
```

`COMPILE_TIME_BASE_KEY` is generated by `spica/build.rs` from `/dev/urandom` and written to `OUT_DIR/keys.rs` as a `u64` hex literal (`pub const COMPILE_TIME_BASE_KEY: u64 = 0x...;`). Hex literals compile to 8-byte immediates; `strings` does not recover them because they are not stored as ASCII.

Build script change: fail the build (not silently produce a zero key) if `/dev/urandom` is unavailable.

### resolve() — visible fallback

```rust
pub fn resolve() -> (u64, KeyOrigin) {
    match TpmKeySource::new() {
        Ok(mut t) => match t.get_random_key() {
            Ok(k) => (k, KeyOrigin::Tpm),
            Err(_) => fallback(),
        },
        Err(_) => fallback(),
    }
}

fn fallback() -> (u64, KeyOrigin) {
    eprintln!("[KEY]        ╔════════════════════════════════════════════╗");
    eprintln!("[KEY]        ║  INSECURE MODE — TPM UNAVAILABLE            ║");
    eprintln!("[KEY]        ║  Compile-time key in use.                  ║");
    eprintln!("[KEY]        ║  Recoverable from the binary.              ║");
    eprintln!("[KEY]        ║  Install on a TPM-equipped host for prod.  ║");
    eprintln!("[KEY]        ╚════════════════════════════════════════════╝");
    (COMPILE_TIME_BASE_KEY, KeyOrigin::CompileTime)
}
```

The banner is unmissable in logs. CI/scripts can grep for `INSECURE MODE` and fail.

### derive_integrity_token() — kept

```rust
pub fn derive_integrity_token(base_key: u64) -> u64 {
    let key_bytes = base_key.to_ne_bytes();
    let mut k = [0u8; 16];
    k[..8].copy_from_slice(&key_bytes);
    k[8..].copy_from_slice(&key_bytes);
    let mut h = siphasher::sip::SipHasher13::new_with_key(&k);
    h.write(b"SPiCaINT");
    h.finish()
}
```

SipHash-1-3 here is a correct MAC use case (deriving a canary from the key without making the canary invertible to the key). Different from the obfuscation decision in §8.

### StaticKey (test only)

```rust
#[cfg(test)]
pub struct StaticKey(pub u64);

#[cfg(test)]
impl KeySource for StaticKey {
    fn get_random_key(&mut self) -> Result<u64, KeyError> { Ok(self.0) }
}
```

---

## 8. Obfuscation — XOR kept

### Decision

Keep the existing XOR-fold obfuscation. Do **not** upgrade to SipHash keystream.

### Reasoning

The known-plaintext attack on XOR (recovering the 64-bit key from predictable `comm` ASCII) requires the adversary to **already have ring buffer ciphertext**. In the constrained eBPF threat model:

- Ring buffers (`sc_sched`, `sc_nmi`) are named maps, enumerable via `bpf()`.
- But reading another program's ring buffer contents requires `bpf_probe_read_kernel` against an address the adversary must first discover — the same capability gap that protects `.bss`.
- An adversary who has broken this gap has already defeated the `.bss` secrecy on which the key's confidentiality rests. SipHash would not save the system at that point.

The SipHash upgrade would defend against an attack that requires already breaking the defense below it. The 0.2% CPU cost (6 SipHash-1-3 calls per event × 10K events/sec) is not justified.

### What changes

- `obfuscate`/`deobfuscate` functions move from `spica-ebpf/src/main.rs` and `spica/src/main.rs` to `spica-common/src/lib.rs` as a single shared function `xor_fields()`.
- Both sides import the same code — single source of truth, no drift.
- Honest label in code comment and README: "obfuscation against read-leakage, not encryption against a capable adversary."

### xor_fields

```rust
// spica-common/src/lib.rs

/// XOR-folds the 64-bit key across all ProcessInfo fields.
/// Symmetric: same function encodes and decodes.
/// event_type is intentionally NOT touched — userspace reads it as a sentinel
/// before calling this function.
#[inline]
pub fn xor_fields(info: &mut ProcessInfo, key: u64) {
    info.pid ^= key as u32;
    info.tgid ^= (key >> 32) as u32;
    info.last_seen ^= key;
    info.start_time_ns ^= key;
    info.cpu ^= key as u32;
    let kb = key.to_ne_bytes();
    for i in 0..8 {
        info.comm[i] ^= kb[i];
        info.comm[i + 8] ^= kb[i];
    }
}
```

---

## 9. eBPF changes

### Removals

From `spica-ebpf/src/main.rs`:

- `use aya_ebpf::{macros::xdp, programs::XdpContext, bindings::xdp_action};`
- `#[map] static sc_net_gate: Array<u32> = Array::with_max_entries(1, 0);`
- `#[xdp] pub fn spica_xdp(ctx: XdpContext) -> u32 { ... }`
- `fn try_xdp(_ctx: XdpContext) -> Result<u32, i64> { ... }`

Net: ~30 lines removed. 4 programs remain (`spica_sched`, `spica_nmi`, `spica_lsm_modblock`, `spica_watchdog`).

### What stays untouched

- All 4 remaining eBPF programs
- All `.bss` globals (`BASE_KEY`, `SPICA_PID`, `INTEGRITY_TOKEN`)
- The `sc_*` named maps (`sc_sched`, `sc_nmi`, `sc_gate`, `sc_wd`, `sc_canary`, `sc_lsm`)
- The canary integrity check in `spica_nmi`
- The GPL license export
- The panic handler

### Obfuscation call site change

In `spica-ebpf/src/main.rs::try_sched` (and `try_nmi`):

```rust
// Before:
let mut info = ProcessInfo { ... };
obfuscate(&mut info, key);

// After:
let mut info = ProcessInfo { ... };
spica_common::xor_fields(&mut info, key);
```

In `spica/src/main.rs` ring buffer consumers:

```rust
// Before:
let raw = unsafe { &*(item.as_ptr() as *const ProcessInfo) };
if raw.event_type == 0 {
    process_event(&deobfuscate(raw, base_key), &mut registry, false);
}

// After (in detect.rs::on_sched_event consumer):
let raw = unsafe { &*(item.as_ptr() as *const ProcessInfo) };
if raw.event_type == 0 {
    let mut info = *raw;
    spica_common::xor_fields(&mut info, base_key);
    detect::on_sched_event(info, &mut registry);
}
```

---

## 10. Userspace `bpf.rs`

Extracts the 95 lines of inline eBPF plumbing (currently `spica/src/main.rs` lines 417-511) into a dedicated module.

### BpfRuntime

```rust
// bpf.rs

pub struct BpfRuntime {
    bpf: Bpf,
    sched_rb: AsyncFd<RingBuf>,
    nmi_rb: AsyncFd<RingBuf>,
    lsm_rb: AsyncFd<RingBuf>,
}

pub struct LsmStatus { pub attached: bool }

impl BpfRuntime {
    /// Load eBPF, set globals, attach programs, pin watchdog, take ring buffers.
    /// Returns the runtime + whether the LSM gate attached (kernel config dependent).
    pub fn load(base_key: u64, spica_pid: u32, integrity_token: u64) -> Result<(Self, LsmStatus)> {
        // 1. Bpf::load(include_bytes_aligned!(...))
        // 2. set_global("BASE_KEY", base_key)
        // 3. set_global("SPICA_PID", spica_pid)
        // 4. set_global("INTEGRITY_TOKEN", integrity_token)
        // 5. Btf::from_sys_fs()
        // 6. Attach spica_sched (BtfTracePoint on sched_switch) — always
        // 7. Attach spica_lsm_modblock (LSM on kernel_read_file) if BPF LSM available
        // 8. Attach spica_watchdog (TracePoint on sched_process_exit) — always
        // 9. Write integrity canary to sc_canary[0]
        // 10. Attach spica_nmi (PerfEvent on HW_CPU_CYCLES, period 10M) on all online CPUs
        // 11. Pin sc_wd → /sys/fs/bpf/spica_watchdog
        // 12. Take ring buffers (sc_sched, sc_nmi, sc_lsm) into AsyncFd
    }

    pub fn lock_lsm_gate(&mut self) -> Result<()> { /* sc_gate[0] = 1 */ }
    pub fn lsm_attached(&self) -> bool { /* ... */ }
}
```

### Ring buffer access

The ring buffer polling stays in `main.rs` using `AsyncFd::readable_mut()` directly so the `tokio::select!` pattern can hold the readiness guards across branches. `BpfRuntime` exposes the `AsyncFd`s via `&mut` accessors:

```rust
impl BpfRuntime {
    pub fn sched_rb_mut(&mut self) -> &mut AsyncFd<RingBuf> { &mut self.sched_rb }
    pub fn nmi_rb_mut(&mut self)   -> &mut AsyncFd<RingBuf> { &mut self.nmi_rb }
    pub fn lsm_rb_mut(&mut self)   -> &mut AsyncFd<RingBuf> { &mut self.lsm_rb }
}
```

The event handlers (`detect::on_sched_event`, etc.) are called from within the `select!` branches in `main.rs`, not from inside `BpfRuntime`. This keeps `BpfRuntime` purely about eBPF lifecycle and keeps detection logic in `detect.rs`.

### Why not trait-abstract BpfRuntime?

Considered `trait EventSource` with a `SyntheticEventSource` for tests. Rejected because:
- The detection functions (`on_sched_event`, `evaluate`) are already pure and testable directly with synthetic `ProcessInfo` / `ProcessRegistry`.
- Mocking the BPF plumbing doesn't add coverage that matters; it adds indirection.
- The Mac-untestable surface (BPF load, attach, ring buffer I/O) stays Mac-untestable either way — a mock doesn't help verify real eBPF behavior.

### Mac dev verification

```makefile
# Makefile addition
check-ebpf:
	cargo check --manifest-path spica-ebpf/Cargo.toml \
	            --target bpfel-unknown-none \
	            -Z build-std=core
```

Catches no_std violations, unused imports, type errors. Does not catch verifier rejection (impossible without loading into a kernel). First real runtime test stays on Linux.

---

## 11. `proc.rs` — kept simple

`proc.rs` contains `read_tgids() -> HashSet<u32>` reading `/proc`. Originally considered trait-abstracting this for testability. Rejected because:
- The function is 10 lines.
- `detect::evaluate()` already accepts `&HashSet<u32>` as input — tests construct synthetic sets directly.
- A trait adds indirection without enabling any test that isn't already possible.

```rust
// proc.rs
pub fn read_tgids() -> std::collections::HashSet<u32> {
    let mut set = HashSet::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(n) = entry.file_name().to_string_lossy().parse::<u32>() {
                set.insert(n);
            }
        }
    }
    set
}
```

---

## 12. `main.rs` orchestration

```rust
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // 1. Watchdog check (previous-run-kill detection)
    if Path::new(WATCHDOG_PIN).exists() {
        println!("[WATCHDOG]   Previous SPiCa instance was not cleanly terminated");
        let _ = fs::remove_file(WATCHDOG_PIN);
    }

    // 2. Security stack audit
    seccheck::run();

    // 3. Resolve key
    let (base_key, origin) = key::resolve();
    if origin == key::KeyOrigin::Tpm {
        println!("[KEY]        TPM key loaded");
    }
    let integrity_token = key::derive_integrity_token(base_key);

    // 4. Load BPF runtime
    let (mut rt, lsm) = bpf::BpfRuntime::load(base_key, std::process::id(), integrity_token)?;
    if rt.lsm_attached() {
        rt.lock_lsm_gate()?;
        println!("[LSM]        Module loading locked — no new LKMs permitted");
    } else {
        eprintln!("[LSM]        BPF LSM unavailable — module blocking disabled");
    }

    // 5. Seed process registry from /proc
    let mut registry = detect::ProcessRegistry::new();
    let startup_nanos = nanos_since_startup();
    for tgid in proc::read_tgids() {
        registry.insert(tgid, detect::ProcessRecord::seeded(startup_nanos));
    }

    // 6. Event loop
    let mut alerts: Vec<detect::Detection> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_millis(TICK_RATE_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sigterm = signal(SignalKind::terminate())?;

    loop {
        tokio::select! {
            guard = rt.sched_rb_mut().readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let raw = unsafe { &*(item.as_ptr() as *const spica_common::ProcessInfo) };
                    if raw.event_type == 0 {
                        let mut info = *raw;
                        spica_common::xor_fields(&mut info, base_key);
                        if let Some(d) = detect::on_sched_event(info, &mut registry) {
                            print_detection(&d);
                        }
                    }
                }
                guard.clear_ready();
            }
            guard = rt.nmi_rb_mut().readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let raw = unsafe { &*(item.as_ptr() as *const spica_common::ProcessInfo) };
                    if raw.event_type == 1 {
                        println!("[TAMPER]     BPF map integrity check failed — sc_canary intercepted");
                    } else {
                        let mut info = *raw;
                        spica_common::xor_fields(&mut info, base_key);
                        if let Some(d) = detect::on_nmi_event(info, &mut registry) {
                            print_detection(&d);
                        }
                    }
                }
                guard.clear_ready();
            }
            guard = rt.lsm_rb_mut().readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let ev = unsafe { &*(item.as_ptr() as *const spica_common::LkmEvent) };
                    let d = detect::on_lkm_event(*ev);
                    print_detection(&d);
                }
                guard.clear_ready();
            }
            _ = tick.tick() => {
                let proc_tgids = proc::read_tgids();
                let now = nanos_since_startup();
                detect::evaluate(&mut registry, &proc_tgids, now, &mut alerts);
                for d in &alerts { print_detection(d); }
            }
            _ = sigterm.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    println!("Catch me! I'll leap over Denebola");
    let _ = fs::remove_file(WATCHDOG_PIN);
    Ok(())
}
```

---

## 13. README rewrite

### Target

~290 lines (down from 580). Narrative voice preserved where it earns space; overclaims replaced with honest framing.

### New outline

```
1. SPiCa                                                    ~20 lines
   - Name etymology (Hatsune Miku song + Alpha Virginis spectroscopic binary)
   - One-sentence description: cross-view eBPF rootkit detector
   - Disclaimer (GLM attribution, not Claude Code)

2. Threat Model                                             ~30 lines
   - LEAD WITH THIS. Detection as primary value, LSM gate as one prevention layer.
   - The constrained adversary: eBPF rootkit (verifier-bounded, can't hook kernel funcs)
   - The non-goal: nation-state kernel exploits (honest)
   - SPiCa as auditor + ultimate validation layer

3. Architecture                                             ~80 lines
   - The sched_switch channel (CO-RE read of task_struct *next, why not helpers)
   - The NMI channel (~100Hz heartbeat, why NMI)
   - The BPF LSM gate (kernel_read_file, EPERM after init window)
   - The watchdog (sched_process_exit, pinned BPF-FS map survives SIGKILL)
   - One short paragraph on the cloud-provider architectural parallel
     (single mention, not three sections)

4. Detection Classes                                        ~40 lines
   - DKOM, GHOST, TAMPER, SILENT, DUPE, LKM-ALLOW/DENY, WATCHDOG
   - One-line definition each + trigger condition
   - The mermaid diagram (kept as-is)

5. Key Management & Obfuscation                             ~40 lines
   - TPM-sourced key via tss-esapi (GetRandom only, no PCR audit — honest)
   - .bss placement + verifier-bounded address secrecy (NOT "Rice's theorem")
   - XOR obfuscation: "obfuscation against read-leakage, not encryption"
   - Compile-time fallback: visible INSECURE MODE banner

6. Defense in Depth                                         ~20 lines
   - Secure Boot → module signing → IMA → SPiCa
   - SPiCa is last-resort, not a substitute
   - check_security_stack output explained

7. Build & Run                                              ~25 lines
   - Prerequisites (kernel version, CONFIG_BPF_LSM, lsm=bpf)
   - make install-deps / install-tools / all / run
   - Mac dev caveat: cargo check works, runtime needs Linux

8. Roadmap                                                  ~15 lines
   - PCR-bound key sealing (real attestation)
   - SipHash PRF upgrade if threat model grows
   - Test coverage expansion
   - Trait-abstracted EventSource for end-to-end tests

9. License & Attribution                                    ~15 lines
   - MIT OR Apache-2.0 clarification
   - GPL note for the eBPF program (kernel requirement)
   - Hatsune Miku character image attribution
```

### Honest reframings (high-stakes prose)

**Rice's theorem → Verifier-bounded address secrecy:**

> The `.bss` globals backing `BASE_KEY`, `SPICA_PID`, and `INTEGRITY_TOKEN` are not enumerable via the `bpf()` syscall's map iteration interface and do not appear in `/proc/kallsyms`. An eBPF adversary with verifier-bounded compute lacks both the *information* (where the address lives) and the *primitives* (unbounded memory scan) to discover them. This is obscurity under capability restriction, not cryptographic secrecy — an LKM could find the key trivially, but LKMs are blocked by the LSM gate. The defense is real, the framing is honest about what it is and isn't.

**XOR obfuscation:**

> The XOR layer obfuscates ring buffer contents against *read-leakage* — an eBPF adversary that finds a way to read the ring buffer sees XOR-folded bytes, not plaintext. This is **not encryption against a capable adversary**: XOR is structurally vulnerable to known-plaintext (predictable `comm` values would recover the key), and the key is recoverable from the userspace binary in TPMless mode. The defense is appropriate for the constrained eBPF adversary (who can't easily read the ring buffer in the first place), not for an adversary with binary access + ring buffer interception.

**TPM:**

> On TPM-equipped hosts, the XOR key is sourced from `TPM2_GetRandom` via `tss-esapi`. The key transits no pipe, no subprocess command line, no disk. On hosts without a TPM, SPiCa falls back to a per-build compile-time key with a visible INSECURE MODE banner. **PCR-bound key sealing (real hardware attestation) is on the roadmap, not in the current implementation.**

### What gets cut

| Current section | Fate |
|---|---|
| "The Old Battle: Kernel Cat and Mouse" (~12 lines) | Condense to 2 sentences in Threat Model |
| "The New Horizon: Establishing Sovereignty..." (~22 lines) | Condense to 3 sentences in Architecture |
| "What Cloud Providers Discovered" (~17 lines) | Cut entirely — same point made in Architecture |
| "Rice's Theorem as Integrity Protection" (~13 lines) | Rewrite as "Verifier-Bounded Address Secrecy" |
| "TPM Key, Hardware Below the Software Stack" (~10 lines) | Rewrite without "attestation" language |
| "Watchdog: Forensic Evidence of a Kill" (~10 lines) | Condense into Architecture |
| Repeated architectural justifications | Each justification appears once |

### What stays

- Hatsune Miku / Spica binary star etymology (project identity)
- The mermaid diagram
- The "defense in depth, last-resort layer" framing
- The narrative voice where it earns its line count
- Build/run instructions
- License/disclaimer

---

## 14. Testing strategy

### Testable on Mac

| Module | Tests | Count |
|---|---|---|
| `detect.rs` | FSM predicates, cooldowns, grace windows, stale eviction, every `ProcessClass` trigger + clear + suppression. Pure functions with synthetic `ProcessRegistry` + `HashSet<u32>`. | ~15 |
| `key.rs` | `derive_integrity_token` round-trip + determinism. `StaticKey` mock for fallback path. TPM impl feature-gated behind `#[cfg(target_os = "linux")]`. | ~5 |
| `spica-common` (`xor_fields`) | Encode/decode symmetry, `event_type` untouched, comm known-plaintext property test (guards against cipher regression). | ~3 |
| `seccheck.rs` | Fixture files for `/proc/cmdline`, efivars binary, `/boot/config-X`. Parsing split from fs reads. | ~5 |

**Total: ~28 unit tests, all run on Mac via `cargo test`.**

### Not testable on Mac

| Module | Coverage |
|---|---|
| `bpf.rs` | `cargo check --target bpfel-unknown-none` for compile errors. Real test on Linux. |
| `spica-ebpf` | Same — `cargo check` only. |
| `main.rs` event loop | Manual smoke test on Linux. |
| Real TPM (`TpmKeySource`) | Linux-only, requires `/dev/tpmrm0`. |

### Example tests

```rust
// detect.rs tests
#[test]
fn dkom_fires_when_scheduled_but_absent_from_proc() {
    let mut reg = ProcessRegistry::new();
    let tgid = 1234u32;
    let now = 5_000_000_000; // 5 sec in
    let mut rec = ProcessRecord::new(/* start_time_ns */ 0, now);
    rec.sched_last = now - 100_000_000; // sched 100ms ago — alive
    reg.insert(tgid, rec);

    let proc_tgids = HashSet::new(); // tgid 1234 hidden from /proc
    let mut out = Vec::new();

    // First tick past grace + suspect threshold
    let later = now + SUSPECT_THRESHOLD_NANOS + 1;
    evaluate(&mut reg, &proc_tgids, later, &mut out);

    assert!(out.iter().any(|d| d.class == DetectionClass::Dkom));
}

#[test]
fn dkom_suppressed_during_cooldown() { /* ... */ }
#[test]
fn dkom_clears_when_process_reappears_in_proc() { /* ... */ }
#[test]
fn tamper_fires_when_nmi_alive_but_sched_silent() { /* ... */ }
#[test]
fn silent_fires_when_both_channels_dead() { /* ... */ }
#[test]
fn ghost_fires_when_in_proc_never_observed() { /* ... */ }
#[test]
fn evaluate_does_not_allocate_when_no_alerts_fire() { /* ... */ }

// key.rs tests
#[test]
fn derive_integrity_token_is_deterministic() { /* ... */ }
#[test]
fn derive_integrity_token_is_not_invertible_to_key() { /* ... */ }
#[test]
fn fallback_emits_insecure_mode_banner() { /* capture stderr, grep */ }

// spica-common tests
#[test]
fn xor_fields_roundtrips() { /* encode then decode == identity */ }
#[test]
fn xor_fields_preserves_event_type() { /* ... */ }

// seccheck.rs tests
#[test]
fn parses_ima_appraise_policy_from_cmdline() { /* fixture */ }
#[test]
fn detects_secure_boot_enabled_from_efivars() { /* fixture binary */ }
```

---

## 15. Cargo / dependency impact

### Workspace `Cargo.toml`

- Add: `tss-esapi = "8"` (or latest compatible) to `[workspace.dependencies]`

### `spica/Cargo.toml`

- Add: `tss-esapi = { workspace = true }`
- Add: `clap = { workspace = true, features = ["derive"] }` (for `install`/`uninstall` subcommands — see §21)
- Remove from aya import list: `Xdp`, `XdpFlags`
- Add: `spica-common = { workspace = true, features = ["..."] }` if features needed

### `spica-ebpf/Cargo.toml`

- Remove from aya-ebpf imports: `xdp`, `XdpContext`, `xdp_action`

### `spica-common/Cargo.toml`

- Unchanged (already no_std-capable, no new deps — `siphasher` already present at workspace level via key.rs use, but not actually needed in common since xor_fields is pure XOR)

---

## 16. Build & Makefile impact

### Makefile additions

```makefile
check-ebpf:
	cargo check --manifest-path spica-ebpf/Cargo.toml \
	            --target bpfel-unknown-none \
	            -Z build-std=core

check: check-ebpf
	cargo check --workspace --exclude spica-ebpf

test:
	cargo test --workspace --exclude spica-ebpf

install:
	sudo ./target/release/spica install

uninstall:
	sudo ./target/release/spica uninstall
```

### Makefile unchanged

- `install-deps` (already installs `tpm2-tools` which pulls in `tpm2-tss` C library on most distros; verify on first Linux test that `libtss2-esys` is present)
- `install-tools`
- `generate-vmlinux`
- `build-ebpf`
- `build`, `all`, `run`, `clean`

### Prereq note

`tss-esapi` requires `tpm2-tss` C library (`libtss2-esys`). Most distros pull this in via `tpm2-tools`. The Makefile's `install-deps` already installs `tpm2-tools` so the C lib is usually transitively present. Add an explicit `pkg-config --libs tss2-esapi` check to `install-deps` for clarity.

---

## 17. Migration / behavior changes

| Behavior | Before | After |
|---|---|---|
| XDP packet block during init | Active | Removed |
| `tpm2_getrandom` subprocess | Used | Replaced by `tss-esapi` direct call |
| `tpm2_pcrread` audit | Printed PCRs | Removed entirely |
| Fallback key warning | Single log line | Multi-line `INSECURE MODE` banner |
| Obfuscation function | Per-side duplicated | Shared via `spica-common::xor_fields` |
| Process record size | ~264 bytes | 96 bytes |
| Per-tick allocation | `Vec<Detection>` per call | Caller-owned reused buffer |
| Detection logic I/O | Inline `println!` | Returns `Vec<Detection>` to caller |
| README claims | Aspirational in places | Verified against code |
| Disclaimer attribution | Claude Code | GLM |
| Initramfs integration | Three loose files in `spica/src/` that user manually copies | `spica install` / `spica uninstall` subcommands; scripts embedded via `include_str!`, distro auto-detected |
| CLI shape | No args (always runs) | `clap`-derived subcommands: `install`, `uninstall`, or no-arg = run |
| Initramfs scripts content | Reference `tpm2_getrandom`/`tpm2_pcrread` subprocess + XDP "network locked" language | Drop subprocess refs (tss-esapi is in-process); drop "network locked" language (XDP gone); libtss2-* copies are now mandatory not just-in-case |

**No detection-semantic changes.** Thresholds, cooldowns, grace windows, alert conditions, and alert classes all preserved exactly.

---

## 18. Roadmap (out of scope for this refactor)

1. **PCR-bound key sealing** — real hardware attestation. At install time, seal the key to expected PCR values; at runtime, unseal fails if PCRs changed. Requires install-time sealing step + sealed blob storage.
2. **SipHash PRF obfuscation** — if threat model grows to include adversaries with ring buffer read access.
3. **Trait-abstracted EventSource** — if end-to-end tests become valuable enough to justify the indirection.
4. **CI pipeline** — Linux smoke tests in GitHub Actions / equivalent, exercising real eBPF load + attach + ring buffer flow.
5. **Benchmarking harness** — measure actual CPU/registry footprint on realistic workloads (2K+ processes).
6. **Additional distro support** — Arch (mkinitcpio), openSUSE (mkinitrd/dracut variant), Void (mkinitramfs). Currently only Debian and Fedora families ship in §21.
7. **`spica status` subcommand** — reports install state + drift detection (binary version vs installed, hook file integrity, etc).

---

## 19. Risks and verifications

| Risk | Mitigation |
|---|---|
| `tss-esapi` API differs from pseudocode in §7 | Verify against actual `tss-esapi` docs on first Linux implementation. The crate's API has shifted across major versions. |
| `bpfel-unknown-none` target not installed on Mac dev | Add to Makefile: `check-ebpf` target fails with clear message if target missing. |
| `tss-esapi` adds heavy compile-time deps | Acceptable trade-off per user decision (less code to maintain). Verify compile time stays reasonable. |
| Detection FSM refactor introduces subtle threshold/cooldown bug | ~15 unit tests covering every `ProcessClass` + cooldown + clear + suppression. Behavior preserved exactly per §17. |
| `ProcessRecord` layout change exposes padding bug | `static_assert_eq` (or `const _: () = assert!(size_of::<ProcessRecord>() == 96);`) to lock the layout. |
| eBPF verifier rejects something after XDP removal | Unlikely (we only removed code), but first Linux run will catch. |
| README rewrite cuts something the user wanted kept | User reviews spec (this doc) before plan is written. |
| `spica install` runs on a box with both dracut and initramfs-tools installed | Detection prefers dracut; document this in `--help` and the install summary print. |
| Initramfs rebuild fails (e.g. `update-initramfs -u` errors mid-way after files are written) | `InstallError::RebuildFailed` includes the exit status; partial install state (hooks written, binary copied) is recoverable by re-running `install` or manually running `uninstall`. |
| Operator runs `spica install` while a previous install is still active (binary running) | Detectable: check `/sys/fs/bpf/spica_watchdog` pin and warn if present before overwriting. |
| Embedded scripts drift from refactor changes (someone re-adds tpm2_getrandom refs) | Success criteria includes grep assertion that `resources/` contains no `tpm2_getrandom`, `tpm2_pcrread`, or "network locked" strings. Add as a CI check. |

---

## 20. Success criteria

- All ~28 unit tests pass on Mac via `cargo test`
- `cargo check --workspace` and `cargo check --target bpfel-unknown-none` both clean on Mac
- `ProcessRecord` size assertion (`== 96`) passes
- No behavior change in detection semantics (verifiable by side-by-side threshold comparison)
- README down to ~290 lines with all honest reframings in place
- GLM attribution in disclaimer
- XDP code fully removed from both sides
- TPM access via `tss-esapi` (no subprocess)
- INSECURE MODE banner fires deterministically when TPM unavailable
- `spica install` succeeds on a Debian/Ubuntu box: binary at `/usr/local/bin/spica`, hook + script at `/etc/initramfs-tools/`, `update-initramfs -u` runs clean, initramfs contains the spica binary
- `spica install` succeeds on a Fedora/RHEL box: dracut module at `/usr/lib/dracut/modules.d/99spica/`, `dracut --force` runs clean
- `spica uninstall` cleanly reverses both, including rebuilding the initramfs without spica
- Install command refuses to run without root with a clear error
- Install command errors clearly on unsupported distros (neither dracut nor initramfs-tools present)
- Embedded scripts in `resources/` have no references to `tpm2_getrandom`, `tpm2_pcrread`, or "network locked"

---

## 21. Install / Uninstall subcommands

### Motivation

The current initramfs integration requires the operator to:
1. Know which initramfs system their distro uses (initramfs-tools vs dracut)
2. Know which of the three loose files in `spica/src/` to copy
3. Know the destination path for each file
4. `chmod +x` each one
5. Run the right rebuild command (`update-initramfs -u` vs `dracut --force`)

`spica install` collapses all five steps into one command. `spica uninstall` reverses it.

### Subcommand dispatch

```rust
// main.rs

#[derive(clap::Parser)]
#[command(version, about = "SPiCa — System Process Integrity & Cross-view Analysis")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Install SPiCa to /usr/local/bin and integrate with initramfs (requires root)
    Install,
    /// Remove SPiCa and its initramfs integration (requires root)
    Uninstall,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Install)   => return install::install().map_err(Into::into),
        Some(Command::Uninstall) => return install::uninstall().map_err(Into::into),
        None => {}  // fall through to normal run
    }
    // ... existing run logic (unchanged from §13)
}
```

No-arg invocation (`sudo spica`) continues to run detection as before. Subcommands are purely additive.

### Module: `install.rs`

```rust
// spica/src/install.rs

use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

const INSTALL_PATH:       &str = "/usr/local/bin/spica";
const WATCHDOG_PIN:       &str = "/sys/fs/bpf/spica_watchdog";

// Debian initramfs-tools paths
const DEB_HOOK_PATH:      &str = "/etc/initramfs-tools/hooks/spica";
const DEB_SCRIPT_PATH:    &str = "/etc/initramfs-tools/scripts/init-premount/spica";

// Fedora dracut paths
const DRAC_MODULE_DIR:    &str = "/usr/lib/dracut/modules.d/99spica";

// Embedded scripts. Lives in spica/resources/ so they stay readable shell
// scripts in source control but ship inside the binary.
const DEB_HOOK:    &str = include_str!("../resources/debian-hook.sh");
const DEB_SCRIPT:  &str = include_str!("../resources/debian-script.sh");
const DRAC_SETUP:  &str = include_str!("../resources/dracut-module-setup.sh");
const DRAC_INIT:   &str = include_str!("../resources/dracut-init.sh");

pub enum Distro { Debian, Fedora }

pub enum InstallError {
    NotRoot,
    DistroUnsupported(String),
    Io(std::io::Error),
    RebuildFailed { cmd: String, status: std::process::ExitStatus },
}

pub fn install() -> Result<(), InstallError> {
    require_root()?;
    let distro = detect_distro()?;
    install_binary()?;

    match distro {
        Distro::Debian => {
            write_executable(DEB_HOOK_PATH,   DEB_HOOK)?;
            write_executable(DEB_SCRIPT_PATH, DEB_SCRIPT)?;
            rebuild("update-initramfs", &["-u"])?;
        }
        Distro::Fedora => {
            fs::create_dir_all(DRAC_MODULE_DIR)?;
            write_executable(&format!("{DRAC_MODULE_DIR}/module-setup.sh"), DRAC_SETUP)?;
            write_executable(&format!("{DRAC_MODULE_DIR}/spica-init.sh"),   DRAC_INIT)?;
            rebuild("dracut", &["--force"])?;
        }
    }
    print_install_summary(distro);
    Ok(())
}

pub fn uninstall() -> Result<(), InstallError> {
    require_root()?;
    let distro = detect_distro()?;

    match distro {
        Distro::Debian => {
            let _ = fs::remove_file(DEB_HOOK_PATH);
            let _ = fs::remove_file(DEB_SCRIPT_PATH);
            rebuild("update-initramfs", &["-u"])?;
        }
        Distro::Fedora => {
            let _ = fs::remove_dir_all(DRAC_MODULE_DIR);
            rebuild("dracut", &["--force"])?;
        }
    }
    let _ = fs::remove_file(INSTALL_PATH);
    let _ = fs::remove_file(WATCHDOG_PIN);  // clear any leftover pin from prior runs
    print_uninstall_summary(distro);
    Ok(())
}

fn detect_distro() -> Result<Distro, InstallError> {
    let dracut = Path::new("/usr/bin/dracut").exists()    || Path::new("/usr/sbin/dracut").exists();
    let initramfs_tools = Path::new("/usr/sbin/update-initramfs").exists()
                       || Path::new("/usr/bin/update-initramfs").exists();
    match (dracut, initramfs_tools) {
        (false, true)  => Ok(Distro::Debian),
        (true,  _)     => Ok(Distro::Fedora),  // prefer dracut if both present
        (false, false) => Err(InstallError::DistroUnsupported(
            "Neither dracut nor initramfs-tools found. SPiCa install supports "
            .to_string() + "Debian/Ubuntu (initramfs-tools) and Fedora/RHEL (dracut)."
        )),
    }
}

fn require_root() -> Result<(), InstallError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(InstallError::NotRoot);
    }
    Ok(())
}

fn install_binary() -> Result<(), InstallError> {
    let current_exe = std::env::current_exe()?;
    fs::copy(&current_exe, INSTALL_PATH)?;
    set_mode(INSTALL_PATH, 0o755)?;
    Ok(())
}

fn write_executable(path: &str, content: &str) -> Result<(), InstallError> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    set_mode(path, 0o755)?;
    Ok(())
}

fn set_mode(path: &str, mode: u32) -> Result<(), InstallError> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

fn rebuild(cmd: &str, args: &[&str]) -> Result<(), InstallError> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        return Err(InstallError::RebuildFailed {
            cmd: format!("{cmd} {}", args.join(" ")),
            status,
        });
    }
    Ok(())
}
```

### Resources directory

```
spica/resources/
  debian-hook.sh            — initramfs-tools hook (was spica-initramfs-hook)
  debian-script.sh          — initramfs-tools init-premount (was spica-initramfs-script)
  dracut-module-setup.sh    — dracut module-setup.sh (extracted from spica-dracut-module.sh heredoc)
  dracut-init.sh            — dracut pre-mount hook (extracted from spica-dracut-module.sh heredoc)
```

### Script updates required for the refactor

All four scripts need three changes from their current form:

1. **Remove `tpm2_getrandom` / `tpm2_pcrread` copy lines.** The refactor switches to `tss-esapi` in-process; the TPM command-line tools are no longer needed at runtime.
2. **Promote `libtss2-*` copies from "just in case" to mandatory.** Since `spica` now dynamically links `libtss2-esys.so.0` (via `tss-esapi`), the library must be in the initramfs. Currently the scripts copy it conditionally; make it unconditional with a clear error if absent.
3. **Drop "network locked" language.** XDP is gone. Success messages become "LKM gate armed" (or just "SPiCa started").

### Migration of existing files

The three current files in `spica/src/` (`spica-initramfs-hook`, `spica-initramfs-script`, `spica-dracut-module.sh`) are deleted. Their content (with the refactor updates above) moves to the four files in `spica/resources/`. The dracut installer shell script is no longer user-facing — its logic is reimplemented in `install.rs` and the two shell scripts it heredoc'd become standalone files in `resources/`.

### Cargo.toml changes

`spica/Cargo.toml` adds:

```toml
clap = { workspace = true, features = ["derive"] }
```

The workspace already declares `clap = { version = "4.5.20", default-features = false, features = ["std"] }` — the spica crate adds the `derive` feature on top.

### Makefile changes

```makefile
# Additions
install:
	sudo ./target/release/spica install

uninstall:
	sudo ./target/release/spica uninstall
```

The existing `run` target stays: `sudo ./target/release/spica` (no subcommand) continues to run detection.

### Testing on Mac

`install.rs` is testable on Mac:
- `detect_distro()` — testable with fixture filesystem layout (trait-abstract the `Path::exists` calls if we want full unit tests; otherwise integration tests on Linux VMs)
- `require_root()` — returns error when not root, trivially testable
- `write_executable()` — testable against a tempdir
- `install()` / `uninstall()` — full end-to-end needs Linux (no `/etc/initramfs-tools/` or `/usr/lib/dracut/` on Mac)

Pragmatic stance: unit-test the helpers (`set_mode`, `write_executable` against tempdir, `detect_distro` with fixture paths behind a trait), integration-test `install`/`uninstall` on the first Linux run. Don't over-engineer Mac coverage for inherently Linux-only operations.

### Error UX

Every `InstallError` variant gets a clear user-facing message:

```
[INSTALL]    Error: must run as root (try `sudo spica install`)
[INSTALL]    Error: neither dracut nor initramfs-tools found on this system.
             SPiCa install supports Debian/Ubuntu (initramfs-tools) and Fedora/RHEL (dracut).
[INSTALL]    Error: `update-initramfs -u` exited with status: exit status: 1
             Initramfs rebuild failed. See system logs above.
```

No silent failures. Every error tells the operator what went wrong and what to do.

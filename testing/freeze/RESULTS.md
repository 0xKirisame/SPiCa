# Freeze & Gate Verification Results

**Host:** Ubuntu 24.04.5 LTS, kernel `6.8.0-14x-generic`, aarch64 (QEMU on Apple Silicon — HVF for rounds 1–2, TCG for rounds 3–4: HVF rejects the TPM MMIO device)
**Kernel BPF LSM:** `lsm=bpf,integrity` active (`/sys/kernel/security/lsm`)
**TPM:** swtpm 0.10.2 vTPM (`tpm-tis-device`), kernel resource manager at `/dev/tpmrm0`
**Date:** 2026-10-09 (R1) · 2026-10-10 (R2) · 2026-10-11 (R3) · 2026-10-12 (R4) · 2026-10-17 (R5 PCR-bound sealing)
**Toolchain:** clang 18, gcc 13, libbpf 1.3, bpftool 7.3, tpm2-tools 5.7; Rust nightly-2026-10-08 + bpf-linker 0.11.1 (musl prebuilt)

## Round 4 — stage-3 completion + rootkit matrix

| Test | Result |
|---|---|
| Link pinning: 10 pins (5 tracepoint/perf programs + per-CPU notary + 2 LSM gates) | **PASS** |
| **SIGKILL survival**: `kill -9` the daemon → `bpftool` still EPERM, `modprobe` still EPERM | **PASS** — protection outlives the process |
| Restart forensics after SIGKILL: watchdog banner + link-pin reap, clean transfer to new instance | **PASS** |
| Knock with wrong token → uninstall refuses | **PASS** |
| Knock with correct token → 60 s window opens, running instance stopped, links detached, pins/watchdog removed, gate fully disarmed after window expiry | **PASS** |
| Lost token (kernel-side token unprovisioned in an early build) → no removal path except reboot | **PASS (by design)** |
| **Diamorphine LKM** (compiled live against headers): `insmod` with gate locked | **PASS** — kernel EPERM + `[LKM-DENY] tgid [insmod]`; module never loads (lsmod clean) |
| Diamorphine retry AFTER daemon SIGKILL | **PASS** — still EPERM (pinned LSM gates) |
| Symbiote-class HOOK / blend-INJECT (earlier rounds of the final build) | **PASS** — see R2/R3 |

## Round 5 — PCR-bound sealing (measured-boot genesis)

| Test | Result |
|---|---|
| `seal-install`: NV secret + PolicyPCR over PCR4+9 (measured boot chain, auto-detected) + PCR23 (binary hash) | **PASS** — H(S) recorded |
| Clean boot: `spica genesis` — binary measured into PCR23, policy unseal, secret to tmpfs | **PASS** |
| Daemon: genesis gate verifies secret vs record → `H(S)` extended into PCR16 as genesis | **PASS** — "genesis bound to sealed boot", PCR16 nonzero |
| **Tamper** (garbage extended into PCR23 ≡ modified binary): genesis | **PASS** — `nv_read under policy FAILED` (policy error), **secret withheld** |
| Tampered boot, daemon start | **PASS** — refuses BEFORE arming anything (no gates, no pins, no system wedge) |
| Sealed install, genesis secret missing | **PASS** — loud refusal, clean exit |

## Round 3 — PCR anchor + unified three-view differential

| Test | Result |
|---|---|
| vTPM attach (swtpm + `tpm-tis-device`) | **PASS** — `/dev/tpmrm0`, PCR16 reads zero at genesis |
| No-TPM degraded mode | **PASS** — loud banner, detector continues in-band only |
| Anchor epochs: extend PCR16 every 10 s with verified chain-head commitments | **PASS** — mirror tracks the TPM exactly while untampered |
| Foreign garbage-extension (`tpm2_pcrextend 16:sha256=…`) | **PASS** — `[PCR-DIVERGE]` within one epoch, persists every epoch, names both digests |
| Restart-within-boot resume (non-zero PCR16 at start) | **PASS** — mirror re-seeded from live value, loud NOTE logged |
| Unified differential `[INJECT]` (libc fabricates a `/proc` entry) | **PASS** — rootkit renaming PID 1's entry to `31337` fired **both** `[HOOK]` (PID 1 hidden) and `[INJECT]` (31337 fabricated) from the same loop |
| Clean system, sustained | **PASS** — 0 TAMPER / 0 PCR-DIVERGE / 0 HOOK / 0 INJECT (notary race fix verified) |

## Round 2 — SPiCa ledger build, live-fire

SPiCa (all 7 eBPF programs, ledger + notary + both LSM gates) built inside the
VM and exercised against live attacks:

| Test | Result |
|---|---|
| Load: 7 programs, freeze verification (`.bss`, `sc_ledger`, `sc_wd`, `sc_gate`), fail-closed checks | **PASS** — all maps sealed, load completes |
| Chain verification under real scheduler load (4 CPUs, sustained) | **PASS** — 0 false TAMPERs (after the tgid-mutation fix, finding 5) |
| Deny-by-default `bpf()` gate vs. `bpftool prog` / `bpftool map` from another root shell | **PASS** — `Operation not permitted` |
| LKM gate: `modprobe rtc-max77686` with gate closed | **PASS** — kernel EPERM + `[LKM-DENY] tgid:20944 [modprobe]` forensic event |
| Symbiote-class HOOK: system-wide `ld.so.preload` hiding a live PID, SPiCa started infected | **PASS** — `[HOOK] 1 PID(s) hidden from libc readdir` within the first ticks |
| Notary on hardware PMU | **N/A in QEMU** — no virtual PMU; software-event fallback engaged (degraded mode, logged loudly) |

## Round 1 — harness suite

| Test | Claim under verification | Result |
|---|---|---|
| T1 | `.bss` globals leak via `BPF_MAP_GET_FD_BY_ID` + `LOOKUP_ELEM`/`bpftool map dump id` | **PASS** — `base_key 0xcaf000d0beef1234` read by a separate process (the blunder, empirically) |
| T2 | Pre-freeze `BPF_MAP_UPDATE_ELEM` rewrites `.bss` state (heartbeat-spoof hole) | **PASS** — spoofed heartbeat written and read back |
| T3 | `bpf_map_freeze()` → syscall update returns `EPERM` | **PASS** |
| T4 | Program writes to frozen map keep working | **PASS** — seq + ktime heartbeat advanced past freeze |
| T5 | fdinfo reports `frozen: 1` | **PASS** |
| T6 | Second freeze is rejected (sealed signal) | **PASS** — rejected with **`EPERM`**, not EBUSY (see finding 1) |
| T7 | Cross-process freeze — no owner authentication | **PASS** — `bpftool map freeze` from another shell sealed our map |
| T8a | `lsm/bpf` TGID self-exemption works | **PASS** — exempt loader kept enumerating |
| T8b | Deny-wins LSM stacking | **PASS** — bpftool denied (`EPERM`) while a second allow-all `lsm/bpf` program was attached |

## Findings that changed SPiCa code

1. **Second-freeze observable is `EPERM`, not `EBUSY` (v6.8).** `map_get_sys_perms()`
   strips `FMODE_CAN_WRITE` from frozen maps, so a second `BPF_MAP_FREEZE` fails the
   permissions check (syscall.c:2021) before the already-frozen `EBUSY` path
   (syscall.c:2031). SPiCa's freeze verification originally expected `EBUSY` and
   would have aborted every load — fixed to accept `EPERM | EBUSY` (spica/src/bpf.rs,
   `freeze_fd`).

2. **libbpf skeletons cannot freeze their own `.bss`.** Skeletons hold a writable
   mmap of global-data maps (that's what `skel->bss` is), and `map_freeze` returns
   `EBUSY` while `writecnt != 0` (writable mmap outstanding). SPiCa's aya loader is
   unaffected — aya writes initial globals through the update syscall and holds no
   persistent mapping — but this is a hard constraint for any libbpf-based
   implementation: drop the mmap before freezing, or use the raw object API.

3. **Freeze has no owner authentication** (T7): any privileged process holding a
   writable fd can seal any map, including someone else's, irreversibly. SPiCa
   defuses this architecturally: every map it creates is frozen at load by design,
   and an attacker freezing the gate map *early* merely does SPiCa's work sooner;
   freezing it while open (gate=0) is detected as an EPERM on SPiCa's own gate-close
   write → fail-closed abort.

4. **eBPF by-value `[u8; 16]` args emit invalid R11 references.** Passing a 16-byte
   array by value into an inlined function made LLVM's BPF backend marshal stack
   args through R11 — which does not exist on eBPF — verifier: `R11 is invalid`.
   Fixed by bundling `append_ledger`'s arguments into a struct passed by reference.

5. **Userspace chain desync via pre-hash record mutation.** Resolving a SWITCH
   record's thread ID to its /proc TGID *before* chain verification recomputes a
   different head than the kernel's (the hash covers `tgid`) — divergence TAMPER
   storm on every multi-threaded switch in the first live run. Fixed: the resolved
   TGID travels as a separate argument; the record stays pristine for hashing
   (`on_ledger_event(rec, resolved_tgid, ...)`, regression test included).

6. **LSM exit-range rejection from select-fusion.** `if c { -1 } else { 0 }` gets
   fused into branchless mask+negate (`r0 = -r0`) at high opt levels (which level
   fuses varies per program shape!) — the verifier then rejects the exit value as
   an unprovable scalar (`should have been in [-4095, 0]`). Robust fix: a volatile
   side effect inside the deny arm (denial counters `BPF_GATE_DENIES` /
   `LKM_GATE_DENIES`) — side effects cannot be speculated into selects, so the
   branch/phi shape survives every optimization level.

7. **tss-esapi `execute_without_session` sends no auth at all.** `TPM2_PCR_Extend`
   authorizes the PCR handle; sessions `(None, None, None)` map to `ESYS_TR_NONE`
   and the TPM rejects every extend (format-zero error 11). The correct idiom for
   an empty-password authorization is `execute_with_session(Some(AuthSession::Password))`
   (= `ESYS_TR_PASSWORD`). Found live against swtpm; `tpm2_pcrextend` (which uses a
   password session) worked from the start, isolating the difference.

8. **Notary in-flight race is real, not theoretical.** Under QEMU timing, notary
   snapshots landed one record ahead of ring-buffer consumption (seq 71 vs 70) and
   the original single-shot "ahead = suppression" predicate false-TAMPERed. Fix:
   two-stage confirmation — an ahead-notary is tentative; if the chain is still
   behind at the *next* notary (~1 s), suppression is confirmed. In-flight records
   always arrive within a second; suppressed ones never do. Load-independent,
   verified clean over sustained runs (0 false TAMPERs) with regression tests.

9. **`security_bpf` receives the KERNEL copy of `bpf_attr`** (syscall.c:5430
   copies from user *before* the hook at :5433). A knock reading the hook's arg-1
   pointer with the *user* probe never matches. Read kernel pointers with the
   kernel probe — found live when the correct token was rejected.

10. **Verifier state explosion from volatile variable-indexed loop reads.** A
    `for i in 0..32` over `read_volatile(&TOKEN[i])` burned 19 s of kernel CPU
    in `BPF_PROG_LOAD` before we killed it. Macro-unrolled constant-offset reads
    verify instantly. Corollary of finding 4: loops + volatile indexing over
    `.bss` are verifier poison; unroll or index by constants.

11. **Split `.bss.<SYMBOL>` maps escape a `.bss`-only freeze.** `#[used] +
    export_name` globals land in their own ARRAY maps; freezing only the main
    `.bss` left `SPICA_PID` syscall-writable (gate bypass by rewrite — found
    during the knock debug). Fix: freeze every `.bss*` map at load; the freeze
    list is name-prefixed, absent names skipped, present ones must seal.

12. **`override_global(must_exist=false)` fails silently** — the AUTH_TOKEN
    override was a no-op until the symbol got `#[used] + export_name` (the
    BTF-bug-incident fix pattern, now applied to every loader-provisioned
    global). Symptom: kernel-side token all-zero → knock structurally
    impossible. Loud lesson: provisioned globals must be exported symbols.

13. **`pkill -x spica` in the uninstaller killed the uninstaller** — same
    binary name. Self-excluding /proc scan instead.

14. **PCR17-22 are DRTM-locality-locked.** swtpm (PC Client spec) rejects
    extends with `TPM_RC_LOCALITY` — debug range 17-22 belongs to dynamic
    RTM. The application-support PCR **23** (the LUKS/Clevis slot) is the
    correct choice; SPICA_BIN_PCR moved there.

15. **`policy_pcr`'s pcrDigest is the HASH of the concatenated PCR values.**
    Three sha256 PCRs concatenated = 96 bytes > the 64-byte TPM2B_DIGEST
    cap (`WrongParamSize` live). Hash the concatenation (install, expected
    values) or pass it empty (genesis — the TPM digests the actual PCRs
    itself, which is exactly the binding check).

16. **A raw TPM handle value is not an ESYS_TR.** Using 0x01700001 directly
    as an ESYS handle → `Unknown ESYS handle (0x07000b)`. It must be
    deserialized with `tr_from_tpm_public`.

17. **A refusing daemon must not leave the gates armed.** The first
    genesis-gate implementation ran AFTER load (pins armed, bpf() denied
    system-wide) — the refusal then exited with everything armed and
    systemd wedged (cgroup BPF EPERM + soft lockup, live). Fix: the entire
    sealed-installation check runs BEFORE any kernel state is armed.

## Harness

```
# in the VM (packages: build-essential clang llvm libelf-dev libbpf-dev bpftool)
INCS="-I/usr/include/$(uname -m)-linux-gnu"
clang -target bpf -O2 -g $INCS -c test.bpf.c -o test.bpf.o
clang -target bpf -O2 -g $INCS -c gate.bpf.c -o gate.bpf.o
gcc harness.c      -o harness      -lbpf -lelf -lz
gcc gate_harness.c -o gate_harness -lbpf -lelf -lz
./harness && ./gate_harness
```

`harness.c` deliberately uses the raw libbpf object API (no skeleton) to mirror
aya's loader pattern — see finding 2.

Full SPiCa build in-VM (round 2): rustup nightly + `rust-src`, bpf-linker 0.11.1
musl prebuilt from GitHub releases (no LLVM dev libs needed), then
`cargo build --release`.

Operational footgun for remote test drivers: `pkill -f target/release/spica`
matches the SSH shell's own command line and kills the session — use `pkill -x spica`.


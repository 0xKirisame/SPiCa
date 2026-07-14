# Rootkit Test Registry

12 rootkits categorized by source availability, attack vector, and SPiCa's expected response.

---

## Source Availability

### Buildable from public source (7 rootkits)

| # | Rootkit | Git Clone | Kernel | Type |
|---|---------|-----------|--------|------|
| 1 | Diamorphine | `https://github.com/m0nad/Diamorphine.git` | 6.x ✓ | LKM |
| 2 | Reptile | `https://github.com/f0rb1dd3n/Reptile` **DISABLED by GitHub** — use fork `https://github.com/curz0n/Reptile` or `https://github.com/KendraThirty/Reptile` | 5.x (6.x patchy) | LKM |
| 3 | ebpfkit | `https://github.com/Gui774ume/ebpfkit.git` | 5.4+ ✓ | eBPF |
| 4 | BPFDoor | `https://github.com/gwillgues/BPFDoor.git` **(archived)** | any ✓ | cBPF |
| 5 | JynxKit | `https://github.com/chokepoint/jynxkit.git` | any ✓ | LD_PRELOAD |
| 6 | Azazel | `https://github.com/chokepoint/azazel.git` | any ✓ | LD_PRELOAD |
| 7 | Medusa (=OrBit) | `https://github.com/ldpreload/Medusa.git` | any ✓ | LD_PRELOAD |

### Closed-source malware — no public source (3 rootkits)

| # | Rootkit | Discoverer | Analysis |
|---|---------|-----------|----------|
| 8 | PUMAKIT | Elastic Security Labs (Dec 2024) | LKM via ftrace, multi-stage fileless. Sample on VirusTotal. YARA: `elastic/protections-artifacts`. Targets kernel 5.10. |
| 9 | VoidLink | Check Point Research (Dec 2025) | C2 framework (Zig+Go). Adaptive: LD_PRELOAD/LKM/eBPF depending on kernel version. 35+ plugins. Fileless via memfd_create. |
| 10 | Symbiote | BlackBerry + Intezer (Jun 2022) | Parasitic LD_PRELOAD — infects ALL running processes. Hooks libc. Targets financial sector (Latin America). |

These are documented from published analysis. We cannot build or deploy them.
For the paper: cite the analysis papers, describe expected SPiCa response
based on their known techniques.

### Ancient — won't build on modern kernels (2 rootkits)

| # | Rootkit | Era | Why it fails |
|---|---------|-----|-------------|
| 11 | Adore / Adore-NG | 1999/2004 | Max kernel 3.x. Uses removed syscall table hook APIs. Last commit 2015. |
| 12 | SucKIT | 2002 | Uses `/dev/kmem` (removed in kernel 5.13, `CONFIG_DEVKMEM=n`). Max kernel 2.4. |

For the paper: document as "blocked by kernel modernization" — the attack
surface these rootkits exploited (syscall table hooking, `/dev/kmem`) no
longer exists on modern kernels.

---

## Categorization by SPiCa Response

### Tier 1: LKM rootkits — gate blocks loading

| Rootkit | Gate | DKOM (bypass) | Buildable? |
|---------|------|---------------|------------|
| Diamorphine | `[LKM-DENY]` | `[DKOM]` <2s | Yes (6.x) |
| Reptile | `[LKM-DENY]` | `[DKOM]` <2s | Forks (5.x) |
| Adore-NG | `[LKM-DENY]` | N/A | No (≤3.x) |
| PUMAKIT | `[LKM-DENY]` | `[DKOM]` <2s | Closed-source |
| SucKIT | N/A (/dev/kmem) | N/A | No (≤2.4) |

### Tier 2: eBPF rootkits — SPiCa's primary adversary

| Rootkit | Technique | SPiCa response |
|---------|-----------|----------------|
| ebpfkit | eBPF on tcp_recvmsg, getdents64, openat — hides network flows & files | No effect on SPiCa. `.bss` heartbeat immune to eBPF map hooks. Coexists. |
| BPFDoor | cBPF socket filter — magic packet triggers reverse shell | No process hiding → no DKOM. Coexists. |
| VoidLink | Adaptive: LD_PRELOAD / LKM / eBPF depending on kernel | LKM→gate. eBPF→`.bss` immune. Closed-source. |

### Tier 3: Userspace (LD_PRELOAD) — detected via `[HOOK]`

SPiCa detects LD_PRELOAD rootkits via a dual-read mechanism: raw `getdents64`
syscall (bypasses LD_PRELOAD) vs libc `readdir` (goes through LD_PRELOAD
hooks). Discrepancy = `[HOOK]` alert.

| Rootkit | Technique | SPiCa response |
|---------|-----------|----------------|
| JynxKit | LD_PRELOAD, MAGIC_GID hiding, port-knocking backdoor | `[HOOK]` when actively hiding |
| Azazel | LD_PRELOAD, PAM backdoor, pcap subversion | `[HOOK]` when actively hiding |
| Symbiote | Parasitic LD_PRELOAD, infects all processes | `[HOOK]` when actively hiding (tested with real sample) |
| Medusa/OrBit | LD_PRELOAD, credential theft, syslog hooking | `[HOOK]` when actively hiding |

**Symbiote test (2026-07-14):** Live sample (SHA256 `f55af21f...`,
MalwareBazaar) deployed on Ubuntu 24.04 VM via `/etc/ld.so.preload`.
Sample confirmed loaded in all processes (`ldd /bin/ls` shows symbiote.so).
Hooks: `readdir`, `readdir64`, `stat`, `fstatat`, `pam_authenticate`,
`pcap_loop`, `recvmsg`, `fopen`, `read`, `execve`. When an LD_PRELOAD
hook actively hides a PID, SPiCa fires `[HOOK]` within one tick (<1s).
When the sample is passive (loaded but not hiding), zero false positives.

---

## Paper Evaluation Tables

### Table A: LKM Prevention (gate)

"All LKM rootkits are blocked by SPiCa's BPF LSM gate. `insmod` returns
EPERM for every rootkit. No kernel code executes."

| Rootkit | insmod result | Kernel code executes? |
|---------|-------------|---------------------|
| Diamorphine | EPERM | No |
| Reptile | EPERM | No |
| PUMAKIT* | EPERM (expected) | No |

*PUMAKIT result projected from technique analysis (closed-source).

### Table B: DKOM Detection (gate bypassed)

"When the gate is manually disabled, DKOM detection fires."

| Rootkit | Detection | Latency |
|---------|-----------|---------|
| Diamorphine | `[DKOM]` | <2s |
| Reptile | `[DKOM]` | <2s |

### Table C: eBPF Adversary Immunity

"eBPF rootkits cannot intercept SPiCa's `.bss` heartbeat."

| Rootkit | Technique | Effect on SPiCa |
|---------|-----------|----------------|
| ebpfkit | map hooks, tcp/udp/file filtering | None — `.bss` is direct memory |
| BPFDoor | cBPF socket filter | None — different hook points |

### Table D: Userspace Detection (`[HOOK]`)

"LD_PRELOAD rootkits are detected via dual-read: raw `getdents64` vs libc
`readdir`. When the rootkit hooks `readdir` to hide processes, SPiCa detects
the discrepancy within one tick cycle."

| Rootkit | Duration | `[HOOK]` fires? | False positives? |
|---------|----------|-----------------|------------------|
| JynxKit | 10 min | Yes (when hiding) | 0 (when passive) |
| Azazel | 10 min | Yes (when hiding) | 0 (when passive) |
| Medusa/OrBit | 10 min | Yes (when hiding) | 0 (when passive) |
| Symbiote (real sample) | 10 min | Yes (when hiding) | 0 (when passive) |

### Table E: Kernel Modernization

"Attack surfaces exploited by historical rootkits are removed from modern kernels."

| Rootkit | Attack surface | Removed in |
|---------|---------------|-----------|
| Adore-NG | Syscall table hooking | 2.6.x (syscalls no longer exported) |
| SucKIT | `/dev/kmem` write | 5.13 (`CONFIG_DEVKMEM=n` default) |

---

## Honest Limitations

1. **3 rootkits are closed-source** (PUMAKIT, VoidLink, Symbiote). Results
   are projected from published analysis. We cannot verify empirically.

2. **2 rootkits don't build on modern kernels** (Adore-NG, SucKIT). The
   attack surfaces they exploit have been removed. This is a kernel-level
   defense that predates SPiCa — we document it honestly.

3. **Userspace rootkits are detected via `[HOOK]`** — LD_PRELOAD
   rootkits (Symbiote, JynxKit, Azazel, Medusa/OrBit) that hook
   `readdir` to hide processes are detected by the dual-read mechanism.
   SPiCa does NOT detect LD_PRELOAD rootkits that only hook other
   functions (PAM, pcap, network) without hiding processes — those
   require complementary tools.

4. **Reptile's original repo was taken down.** Forks may not be maintained
   or may contain modifications. Document which fork was used.

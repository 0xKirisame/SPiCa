# SPiCa Evaluation Methodology

> Designed for NDSS / USENIX Security submission rigor. Every test is
> automated, deterministic, and reproducible from the scripts in this
> directory.

---

## 1. Test Environment

### 1.1 VM Configuration

Three distros representing the major Linux families:

| Distro | Kernel | Family | Base Image |
|--------|--------|--------|------------|
| Ubuntu 24.04 LTS | 6.8 | Debian-derived | `ubuntu-base.qcow2` |
| Fedora 40 | 6.10 | Red Hat-derived | `fedora-base.qcow2` |
| Debian 12 (Bookworm) | 6.1 | Debian | `debian-base.qcow2` |

Each base image is a **minimal server install** (no GUI) with SSH enabled and
an SSH public key in `/root/.ssh/authorized_keys`. Base images are read-only;
every test runs on a fresh overlay snapshot and is discarded afterward.

### 1.2 Hardened VM Boot

All VMs boot with the full security stack that SPiCa expects:

```
QEMU flags:
  - UEFI Secure Boot (OVMF with secboot)
  - vTPM 2.0 (swtpm emulator)
  - KVM acceleration
  - 4 vCPU, 4 GB RAM
  - virtio-net with SSH port forwarding (localhost:2222)

Kernel command line:
  lsm=bpf,integrity
  ima_policy=appraise_tcb
  ima_appraise=enforce
  module.sig_enforce=1
```

### 1.3 Kernel Requirements (verified at boot)

SPiCa checks the security stack at startup and prints status. The VM
configuration must produce:

```
[STACK]      Secure Boot ...............  OK
[STACK]      Module signing (SIG_FORCE)   OK
[STACK]      IMA active .................  OK
[STACK]      IMA module appraise policy   OK
[KEY]        TPM key loaded
[LSM]        Module loading locked — no new LKMs permitted
```

If any layer shows MISSING, the test is invalid and the VM configuration
must be fixed before proceeding.

---

## 2. Threat Categories

### 2.0 Tested results (Ubuntu 24.04, kernel 6.8.0-134)

Results from live VM testing on 2026-07-14:

| Rootkit | Type | Gate | Detection | Latency |
|---------|------|------|-----------|---------|
| Diamorphine | LKM/DKOM | `[LKM-DENY]` blocked | N/A | <1s |
| Singularity (MatheuZSecurity) | LKM + ftrace + anti-eBPF | `[LKM-DENY]` blocked | `[TAMPER]+[SILENT]` when bypassed | <5s |
| Symbiote (MalwareBazaar f55af21f) | LD_PRELOAD parasitic | N/A (userspace) | `[HOOK]` when actively hiding; 0 FP when passive | <1s |

Key findings:
- Singularity's `bpf_map_*` hooks are **ineffective** against SPiCa's `.bss` heartbeat (direct memory store, not a map operation).
- Singularity's `__bpf_prog_run` hook blocks sched_switch execution, but this **stops the heartbeat from being written** — the NMI detects the frozen heartbeat via `.bss` read and fires `[TAMPER]`.
- Symbiote's `readdir` hook is detected by SPiCa's dual-read: `getdents64` (raw syscall, bypasses hooks) vs libc `readdir` (goes through hooks). Discrepancy = `[HOOK]`.

### 2.1 LKM-based rootkits (R1–R3)

Test that the LSM gate blocks module loading. Then test DKOM detection
when the gate is bypassed (manual insmod with gate disabled).

| ID | Rootkit | Technique | Expected |
|----|---------|-----------|----------|
| R1 | Diamorphine | `insmod diamorphine.ko` | `[LKM-DENY]` (gate blocks) |
| R2 | Diamorphine (gate disabled) | Process hiding via DKOM | `[DKOM]` within 2s |
| R3 | Reptile | Container/process hiding | `[LKM-DENY]` or `[DKOM]` |

### 2.2 eBPF-based attacks (R4–R7)

The primary threat model. Custom eBPF programs that target SPiCa's
observation channels.

| ID | Attack | Technique | Expected |
|----|--------|-----------|----------|
| R4 | Tracepoint detach | Remove SPiCa from sched_switch funcs | `[TAMPER]` within 2s |
| R5 | bpf_override_return | Attempt to override sched_switch dispatch | No effect (void function, not ALLOW_ERROR_INJECTION) |
| R6 | Kill SPiCa | `kill -9 $(pidof spica)` | `[WATCHDOG]` on next start |
| R7 | Ring buffer drain | Advance consumer pointer to drop events | `[SILENT]` within 5s |

### 2.3 Channel death (R8–R9)

Simulate the original BTF bug and hardware failure.

| ID | Attack | Technique | Expected |
|----|--------|-----------|----------|
| R8 | sched_switch silent | `bpftool prog detach` on sched tracepoint | `[TAMPER]` (heartbeat frozen) |
| R9 | NMI perf event disable | Zero perf_event state or detach | `[SILENT]` (NMI heartbeat absent) |

### 2.4 Negative tests (N1–N3)

Clean system, no rootkit. Verify zero false positives.

| ID | Workload | Duration | Expected |
|----|----------|----------|----------|
| N1 | Idle (no workload) | 10 min | 0 alerts |
| N2 | Desktop workload (compile, browse) | 1 hour | 0 alerts |
| N3 | Stress test (stress-ng, fork storm) | 10 min | 0 alerts |

---

## 3. Metrics

### 3.1 Detection effectiveness

For each rootkit test (R1–R9):

- **Detected?** Yes / No / Partial
- **Detection class** Which alert fired (DKOM, TAMPER, SILENT, etc.)
- **Detection latency** Time from attack deployment to first alert (seconds)
- **System stability** Did the VM crash? Did the kernel panic?

### 3.2 False positive rate

For each negative test (N1–N3):

- **Total alerts** over the test duration
- **FP rate** = alerts / hours
- **Alert breakdown** which classes fired, if any

### 3.3 Performance overhead

Measured with SPiCa running vs baseline:

- **CPU utilization** (idle and under load)
- **Context switch latency** (`perf bench sched messaging`)
- **Memory overhead** (RSS of spica process + BPF maps)
- **Network throughput** (`iperf3`) — should be unaffected
- **Disk I/O** (`fio`) — should be unaffected

### 3.4 NMI heartbeat statistics

- **Heartbeat events/sec** (steady state, should be ~1/sec)
- **SCHED_HEARTBEAT update rate** (should match scheduler frequency)
- **Ring buffer fill rate** (sched + NMI channels)

---

## 4. Procedure

Each test follows this exact sequence:

```
1. Create overlay:      qemu-img create -f qcow2 -b $BASE -F qcow2 $OVERLAY
2. Boot hardened VM:    boot-hardened.sh $OVERLAY
3. Wait for SSH:        retry until VM is reachable on :2222
4. Verify stack:        ssh root@vm 'dmesg | grep -i bpf' (confirm BPF LSM)
5. Install SPiCa:       scp target/release/spica root@vm:/usr/local/bin/
6. Start SPiCa:         ssh root@vm 'spica &' (capture PID)
7. Wait for healthy:    5 seconds, verify no startup alerts
8. Deploy attack:       ssh root@vm 'bash deploy.sh'
9. Wait for detection:  poll SPiCa output for up to 30 seconds
10. Record result:      timestamp, alert class, latency
11. Shutdown VM:        ssh root@vm 'poweroff' (overlay discarded)
```

### 4.1 Result format

Results are written to `testing/results/` as JSON:

```json
{
  "test_id": "R2-diamorphine-dkom-ubuntu",
  "distro": "ubuntu-24.04",
  "kernel": "6.8.0-31",
  "timestamp": "2026-07-13T14:22:01Z",
  "detected": true,
  "alert_class": "DKOM",
  "latency_sec": 2.1,
  "system_stable": true,
  "spica_output": "..."
}
```

### 4.2 Result matrix

The final paper presents results as:

**Table: Detection Effectiveness (R1–R9 × 3 distros)**

| Test | Ubuntu | Fedora | Debian |
|------|--------|--------|--------|
| R1 | ✓ LKM-DENY <1s | ✓ LKM-DENY <1s | ✓ LKM-DENY <1s |
| R2 | ✓ DKOM 2.1s | ✓ DKOM 2.0s | ✓ DKOM 2.2s |
| ... | ... | ... | ... |

**Table: False Positives (N1–N3 × 3 distros)**

| Test | Ubuntu | Fedora | Debian |
|------|--------|--------|--------|
| N1 (10min idle) | 0 | 0 | 0 |
| N2 (1hr load) | 0 | 0 | 0 |
| N3 (stress) | 0 | 0 | 0 |

**Table: Performance Overhead**

| Metric | Baseline | +SPiCa | Δ |
|--------|----------|--------|---|
| CPU idle | 0.3% | 0.4% | +0.1% |
| ... | ... | ... | ... |

---

## 5. Rootkit Sources

| Rootkit | Repository | Version | Build |
|---------|-----------|---------|-------|
| Diamorphine | github.com/m0nad/Diamorphine | master | make (against VM kernel headers) |
| Reptile | github.com/f0rb1dd3n/Reptile | master | make |
| Custom eBPF | testing/rootkits/bpf-detach/ | — | cargo build --target bpfel-unknown-none |

Custom eBPF attack programs are written in this repository under
`testing/rootkits/`. They target SPiCa's specific defenses and are
designed to exercise each detection class.

---

## 6. Threats to Validity

Stated honestly for the paper:

1. **VM vs bare metal** — KVM provides hardware virtualization, but some
   NMI/PMU behaviors may differ from bare metal. Bare-metal testing on
   at least one system is recommended for camera-ready.

2. **Kernel version coverage** — Three distros cover three kernel
   versions (6.1, 6.8, 6.10). Older kernels (< 5.15) are not tested.

3. **Rootkit coverage** — Only open-source rootkits are tested.
   Proprietary or nation-state rootkits are not available.

4. **Single-attacker model** — Tests assume one attack at a time.
   Combinations (DKOM + tracepoint detach simultaneously) are noted as
   future work.

5. **TPM emulation** — swtpm provides a software TPM. Hardware TPM
   testing is recommended for final validation of PCR-bound sealing
   (future work).

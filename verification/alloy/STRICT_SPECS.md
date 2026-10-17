# SPiCa Strict Specification — Owner-Exclusive .bss Access (v2)

## Restricted-Environment Model

**Model:** `verification/alloy/owner_exclusive_access.als`
**Result:** All 9 checks HOLD; all 3 demonstrations SAT

---

## Environment Constraints (E1–E4, deployment-specific, load-bearing)

| # | Constraint | Effect on model |
|---|-----------|-----------------|
| E1 | Restricted eBPF set: no tail calls, no inter-program communication | No TailCall/comm sigs exist at all; adversary = ONE program per load. Retires rate limiting. |
| E2 | Detector consumes verifier fixed-point end product (provenance edges) | `DataflowEdge` relation holds for ALL executions; ALU laundering cannot blur it |
| E3 | No profilers in threat environment | The oracle signature has no legitimate population; zero-FP budget |
| E4 | LSM armed in initramfs | No boot window; `gateArmed` precedes any adversary load |

---

## v1 → v2: What Changed

| Path C defense | v1 | v2 |
|---|---|---|
| Mechanism | `BPF_PROG_LOAD` rate limiting | Scan-oracle detector on verifier-state dataflow |
| Coverage | Bounds binary search (all variants) | **Eliminates** the oracle at load time |
| Evasions | Tail-call split (bounded only), ALU laundering (invisible) | Both structurally impossible (E1, E2) |
| Side effect | Rate-limits ALL non-Owner loads | Surgical: only probe→branch/store programs rejected |
| In main theorem | Required conjunct | **Removed** — SPEC 7'/8' hold without it |

## The Scan-Oracle Signature

`bpf_probe_read_kernel` returns 0 on hit / negative on fault — the
return value IS the secret bit. **Information-theoretic completeness:**
for that bit to be exfiltrated, it must influence control flow
(conditional jump) or data flow (map store). No influence ⇒ no channel.

```
scanOracle = some p: ProbeReadI, sink: Instr |
             (sink in CondJumpI or sink in MapStoreI)
             and p->sink in reaches        // verifier end-product edges
```

Covers both constructible variants (both demonstrated SAT):

| Variant | Shape | ktime needed? | Caught by |
|---|---|---|---|
| A — ktime-delta | `ktime; probe; ktime; branch(delta); store` | yes | probe→branch edge |
| B — spin-exfil | `probe; branch(retval); hit→spin, miss→exit` — userspace measures wall-clock | **no** | probe→branch edge |

Variant B is why the signature keys on *influence* (probe→branch/store)
rather than surface features (ktime pairs). The Alloy instance for
Variant B contains zero `KtimeI` atoms — a ktime-pairing detector
would miss it; the influence detector cannot.

---

## Spec Chain v2

```
COUNTEREXAMPLE (original model)   DEFENSE                    SPEC                    RESULT
──────────────────────────────────────────────────────────────────────────────────────────
GateNotNeeded                     LSM Gate (E4)              SPEC 1,2,3              HOLDS
FullDefenseAbsolute               kASLR + Verifier budget    SPEC 4,5                HOLDS
TimingIsSafe                      Scan-Oracle Detector (E2)  SPEC 6'                 HOLDS
                                  ── composition ──          SPEC 7' (no rate limit) HOLDS
                                                             SPEC 8' MAIN THEOREM    HOLDS
──────────────────────────────────────────────────────────────────────────────────────────
Necessity: gate                   GateIsNecessary            check                  HOLDS
Necessity: detector               oracleVariantA/B runs      run                    SAT
Precision: blind scans allowed    blindScanPassesDetector    run                    SAT
```

**SPEC 8' (Main Theorem) — rate-limit-free:**
```
ownerHasAccess ∧ no-adversary-fd ∧ gate-blocks-fd-acquisition
∧ detector-blocks-oracle ∧ budget-leaves-unprobed-address
⇒ the only path to .bss is the Owner's exclusive fd
```

---

## Remaining Probabilistic Residue (accepted)

The blind linear scan (probes influencing nothing) still passes the
detector *by design* — it is not an oracle, and SPEC 4/5 already bound
it probabilistically (pigeonhole + kASLR, P ≈ 10⁻²⁴ per load). The
detector is surgical; the budget is the backstop.

## Out of Model (unchanged from README §1 non-goals)

- Verifier unsoundness (CVE-class) — E2 assumes a correct verifier
- `ptrace`/`/proc/pid/mem` same-privilege reads — off-host logging only
- Compromise of the Owner process itself

---

## Reproducing

```bash
cd verification/alloy
./run_all.sh        # both models (original + strict v2)
```

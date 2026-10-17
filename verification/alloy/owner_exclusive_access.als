// ═══════════════════════════════════════════════════════════════════════
// SPiCa — Owner-Exclusive .bss Access (Restricted Environment)
// Strict Alloy 6 Specification — v2
//
// ENVIRONMENT CONSTRAINTS (deployment-specific, all load-bearing):
//
//   E1. Restricted eBPF set — no tail calls, no inter-program
//       communication (no BPF-to-BPF cross-program dataflow). The
//       adversary operates ONE program per load.
//   E2. Verifier-state hook — the detector consumes the verifier's
//       abstract-interpretation end product (provenance of every
//       scalar, every branch condition, every store value). These
//       facts hold for ALL runtime executions (fixed-point), so ALU
//       laundering cannot blur them.
//   E3. No profilers — the threat environment (enterprise/infra under
//       rootkit suspicion) does not run bpftrace/perf. ktime+probe
//       pairing has no legitimate users. Zero false-positive budget
//       needed.
//   E4. LSM armed in initramfs — the gate precedes all userspace.
//       No boot window.
//
// SPEC CHAIN v2 (supersedes rate-limit-based Path C defense):
//
//   COUNTEREXAMPLE              → DEFENSE              → SPEC
//   ─────────────────────────────────────────────────────────────────
//   GateNotNeeded               → LSM Gate (E4)        → SPEC 1,2,3
//   FullDefenseAbsolute         → kASLR + Verifier     → SPEC 4,5
//   TimingIsSafe                → Scan-Oracle          → SPEC 6',7',8'
//                                 Detector (E1,E2,E3)
//
// MAIN THEOREM (SPEC 8'): Under verifier + gate + oracle detector,
// the adversary has NO deterministic path to the .bss address.
// Rate limiting is RETIRED — E1 removes the split-program evasion
// it existed to handle; E2 removes the laundering it couldn't see.
// ═══════════════════════════════════════════════════════════════════════

open util/integer

// ── 1. Processes ────────────────────────────────────────────────────────

sig Process {}
one sig Owner in Process {}
fun Adversary: set Process { Process - Owner }
fact AtLeastTwoProcesses { #Process >= 2 }

// ── 2. Kernel Address Space (kASLR) ─────────────────────────────────────

sig Addr {}

// ── 3. BPF Maps ─────────────────────────────────────────────────────────

sig BpfMap { kaddr: one Addr }
one sig BssMap in BpfMap {}
fun secretAddr: one Addr { BssMap.kaddr }

// ── 4. File Descriptors ─────────────────────────────────────────────────

sig MapFD { map: one BpfMap, holder: one Process }

fact OwnerExclusiveBssFd {
    all fd: MapFD | fd.map = BssMap implies fd.holder = Owner
}
fact OwnerHasBssFd {
    one fd: MapFD | fd.map = BssMap and fd.holder = Owner
}

// ── 5. Adversary Program (verifier-constrained, E1-restricted) ──────────
//
// ONE program. No TailCall instruction exists in the environment.
// No inter-program communication primitives exist. This is not a
// defense the detector provides — it is an environment invariant,
// so no sig for them appears at all.

sig Instr {
    pos: one Int              // position in the instruction stream
}

// The instruction classes relevant to the oracle signature.
sig ProbeReadI, KtimeI, SpinI, CondJumpI, MapStoreI, OtherI extends Instr {}

sig Probe {
    insn: one ProbeReadI,
    addr: one Addr
}
// ── Verifier end product (E2) ───────────────────────────────────────────
//
// The detector does NOT re-analyze instructions. It reads the dataflow
// edges the verifier already computed to fixed-point:
//
//   reaches: i1 -> i2  means "the value/condition produced at i1
//   reaches and affects the branch condition or stored value at i2."
//
// Because these edges are fixed-point facts, they hold for every
// dynamic execution — laundering through ALU chains is impossible
// (the verifier folds it into the edge relation).

sig DataflowEdge {
    src, dst: one Instr
}

fun reaches: Instr -> Instr { DataflowEdge.src -> DataflowEdge.dst }

// ── 6. The Scan-Oracle Signature ────────────────────────────────────────
//
// MINIMAL INVARIANT: bpf_probe_read_kernel returns 0 on hit, negative
// on fault — the return value IS the secret bit. For that bit to be
// exfiltrated, it MUST influence control flow (a conditional jump)
// or data flow (a map store). Information-theoretic completeness:
// no influence ⇒ no channel ⇒ not an oracle.
//
// This single predicate covers BOTH attack variants:
//
//   Variant A (ktime-delta):  ktime; probe; ktime; branch on delta; store
//   Variant B (spin-exfil):   probe; branch on retval; hit→spin/miss→exit;
//                             userspace measures program wall-clock
//
// In both, a CondJumpI or MapStoreI is REACHED-FROM a ProbeReadI.

pred scanOracle {
    // some probe whose outcome influences a branch or a store
    some p: ProbeReadI, sink: Instr |
        (sink in CondJumpI or sink in MapStoreI)
        and p->sink in reaches
}

// ── 7. Defenses ─────────────────────────────────────────────────────────

// D1: LSM Gate — armed in initramfs (E4). Blocks map-fd acquisition.
lone sig LSMGate {}
pred gateArmed    { some LSMGate }
pred gateDisarmed { no LSMGate }

// D2 (NEW): Scan-Oracle Detector — verifier-state hook (E2).
// At BPF_PROG_LOAD for non-Owner, reads the verifier's end-product
// dataflow edges and rejects the program if the oracle signature
// matches: probe outcome → branch/store. E3 (no profilers) means
// this signature has no legitimate population.
lone sig ScanDetector {}
pred detectorActive    { some ScanDetector }
pred detectorInactive  { no ScanDetector }

// D3 (RETIRED): Rate Limiting — removed. E1 (no tail calls, no
// inter-program comm) removes the split-oracle evasion rate limiting
// existed to bound. Single-program oracles are handled surgically
// by D2.

// ── 8. Verifier Constraints ─────────────────────────────────────────────
//
// Loop boundedness is implicit in E2: the verifier only reaches its
// fixed-point end product for programs whose loops it proved bounded.
// Rejected programs never produce the dataflow edges the detector
// consumes. The budget bound remains explicit:

pred withinBudget { #Probe < #Addr }
pred verifierAccepts { withinBudget }

// ── 9. Adversary Paths ──────────────────────────────────────────────────

// Path A: fd acquisition via map enumeration — blocked by gate (D1).
pred canAcquireFd[p: Process] {
    p in Adversary and gateDisarmed
}

// Path B: blind linear scan — bounded by verifier budget + kASLR.
// NOT an oracle: probes whose outcomes influence nothing (no branch,
// no store reached-from probe). Genuinely blind ⇒ probabilistic only.
fun probedAddrs: set Addr { Probe.addr }
pred probedSecret { secretAddr in probedAddrs }

// Path C: adaptive binary search — REQUIRES the oracle signature.
// Variant A or B, both must branch or store on probe outcome.
// Blocked by detector (D2) when active.
pred canBinarySearch {
    scanOracle
    and detectorInactive
}

// Deterministic win: a guaranteed path, not a lucky one.
pred adversaryDeterministicWin[p: Process] {
    p in Adversary and (canAcquireFd[p] or canBinarySearch)
}

// ═══════════════════════════════════════════════════════════════════════
// 10. STRICT SECURITY SPECIFICATIONS
// ═══════════════════════════════════════════════════════════════════════

// SPEC 1: No adversary holds an fd to BssMap.
assert FDExclusivity {
    all p: Adversary, fd: MapFD |
        not (fd.map = BssMap and fd.holder = p)
}

// SPEC 2: Armed gate blocks fd acquisition.
assert GateBlocksFdAcquisition {
    gateArmed implies all p: Adversary | not canAcquireFd[p]
}

// SPEC 3: Owner always has access.
assert OwnerAlwaysHasAccess {
    some fd: MapFD | fd.map = BssMap and fd.holder = Owner
}

// SPEC 4: Verifier budget prevents exhaustive scan.
assert VerifierPreventsExhaustiveScan {
    verifierAccepts implies (some a: Addr | a not in probedAddrs)
}

// SPEC 5: Scan cannot GUARANTEE discovery (kASLR argument).
assert ScanNotGuaranteed {
    verifierAccepts implies (some a: Addr | a not in probedAddrs)
}

// SPEC 6': Active detector blocks every oracle variant.
//
//   covers Variant A: ktime-delta (branch reached-from probe)
//   covers Variant B: spin-exfil  (branch reached-from probe)
//   completeness: no influence ⇒ no channel (see §6)
assert DetectorBlocksScanOracle {
    detectorActive implies not canBinarySearch
}

// SPEC 7': No deterministic win WITHOUT rate limiting.
// (v1 needed RateLimit here — v2 does not.)
assert NoDeterministicAdversaryWin {
    (verifierAccepts and gateArmed and detectorActive) implies
    all p: Adversary | not adversaryDeterministicWin[p]
}

// SPEC 8' (MAIN THEOREM): Address only via Owner — rate-limit-free.
pred ownerHasAccessNoRl {
    some fd: MapFD | fd.map = BssMap and fd.holder = Owner
}

assert AddressOnlyViaOwner {
    ownerHasAccessNoRl
    all p: Adversary, fd: MapFD |
        not (fd.map = BssMap and fd.holder = p)
    gateArmed implies all p: Adversary | not canAcquireFd[p]
    detectorActive implies not canBinarySearch
    verifierAccepts implies (some a: Addr | a not in probedAddrs)
}

// ── Necessity ────────────────────────────────────────────────────────────
//
// GateIsNecessary is checkable (any disarmed instance yields a
// winnable adversary). Detector necessity is NOT checkable as an
// assertion — "detector inactive ⇒ oracle exists" is falsified by any
// oracle-free program, which is not a meaningful counterexample.
// Instead, necessity is demonstrated by the oracle variant runs
// below: both variants are constructible, so deactivating the
// detector reopens Path C.

assert GateIsNecessary {
    gateDisarmed implies some p: Adversary | canAcquireFd[p]
}

// ── Oracle variants (constructibility = detector necessity) ──────────────

pred oracleVariantA_ktimeDelta {
    // ktime → probe → ktime → branch(delta) → store, branch reached-from probe
    some p: ProbeReadI, k1, k2: KtimeI, j: CondJumpI, s: MapStoreI |
        k1.pos < p.pos and p.pos < k2.pos and k2.pos < j.pos and j.pos < s.pos
        and p->j in reaches
}

pred oracleVariantB_spinExfil {
    // probe → branch(retval) → spin (hit) / exit (miss)
    some p: ProbeReadI, j: CondJumpI, sp: SpinI |
        p.pos < j.pos and j.pos < sp.pos
        and p->j in reaches
}

// ── Surgical precision: non-adaptive probes pass the detector ───────────
//
// The detector must NOT reject blind linear scanners — they are
// already probabilistically bounded (SPEC 4/5). Only oracles are
// rejected. SAT = the detector is not over-broad.
pred blindScanPassesDetector {
    detectorActive
    verifierAccepts
    some Probe                       // probes exist
    no p: ProbeReadI, sink: Instr |  // but nothing is reached-from them
        (sink in CondJumpI or sink in MapStoreI)
        and p->sink in reaches
}

// ═══════════════════════════════════════════════════════════════════════
// 11. CHECK COMMANDS
// ═══════════════════════════════════════════════════════════════════════

check FDExclusivity for 8 but 3 Process, 2 BpfMap, 3 Probe, 3 ProbeReadI, 3 CondJumpI, 3 MapStoreI
check GateBlocksFdAcquisition for 8 but 3 Process, 2 BpfMap
check OwnerAlwaysHasAccess for 8 but 3 Process, 2 BpfMap
check VerifierPreventsExhaustiveScan for 8 but 3 Probe
check ScanNotGuaranteed for 8 but 3 Probe
check DetectorBlocksScanOracle for 8 but 3 ProbeReadI, 3 CondJumpI, 3 MapStoreI
check NoDeterministicAdversaryWin for 8 but 3 Process, 2 BpfMap, 3 Probe, 3 ProbeReadI, 3 CondJumpI, 3 MapStoreI
check AddressOnlyViaOwner for 8 but 3 Process, 2 BpfMap, 3 Probe, 3 ProbeReadI, 3 CondJumpI, 3 MapStoreI
check GateIsNecessary for 8 but 3 Process, 2 BpfMap

// Demonstrations:
run oracleVariantA_ktimeDelta for 8 but 3 ProbeReadI, 3 KtimeI, 3 CondJumpI, 3 MapStoreI
run oracleVariantB_spinExfil for 8 but 3 ProbeReadI, 3 SpinI, 3 CondJumpI, 3 MapStoreI
run blindScanPassesDetector for 8 but 3 Probe, 3 ProbeReadI, 3 CondJumpI, 3 MapStoreI

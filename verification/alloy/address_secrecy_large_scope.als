// ═══════════════════════════════════════════════════════════════════════
// SPiCa — Address Secrecy: Higher-Scope Checks
// Runs the core assertions at larger scopes to confirm scalability.
// ═══════════════════════════════════════════════════════════════════════

open util/integer

sig Addr {}
one sig Target in Addr {}

abstract sig Instr {}
  sig ProbeRead extends Instr { addr: one Addr }
  abstract sig MapOp extends Instr {}
    sig GetNextId extends MapOp {}
    sig GetFdById extends MapOp {}
    sig LookupElem extends MapOp {}
  sig Other extends Instr {}

sig Block { succs: set Block, instrs: set Instr }
one sig Entry in Block {}

fact InstructionOwnership { all i: Instr | one b: Block | i in b.instrs }
fact AllBlocksReachable { all b: Block | b in Entry.*succs }

fun probedAddrs: set Addr { { a: Addr | some p: ProbeRead | p.addr = a } }

pred withinInstructionBudget { #ProbeRead < #Addr }
pred loopsBounded { no b: Block | b in b.^succs }
pred verifierAccepts { withinInstructionBudget and loopsBounded }

lone sig LSMGate {}
pred gateArmed { some LSMGate }
pred gateDisarmed { no LSMGate }
pred hasMapEnum { some MapOp }
pred canEnumerateMaps { hasMapEnum and gateDisarmed }

lone sig TimingLeak {}
pred timingObservable { some TimingLeak }

pred targetProbed { Target in probedAddrs }
pred adversaryWins {
    canEnumerateMaps or targetProbed or timingObservable
}

// ── Core property: verifier prevents exhaustive scan ────────────────────
assert VerifierPreventsExhaustiveScan {
    verifierAccepts implies (some a: Addr | a not in probedAddrs)
}

// ── Gate blocks enumeration ──────────────────────────────────────────────
assert GateBlocksEnumeration {
    gateArmed implies not canEnumerateMaps
}

// Scope 12: 12 addresses, 5 probes (budget < space)
check VerifierPreventsExhaustiveScan for 12 but 5 ProbeRead, 5 Block, 4 MapOp
check GateBlocksEnumeration for 12

// Scope 16: 16 addresses, 7 probes
check VerifierPreventsExhaustiveScan for 16 but 7 ProbeRead, 6 Block, 5 MapOp
check GateBlocksEnumeration for 16

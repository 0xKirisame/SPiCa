// Minimal model for per-command scope-8 verification
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
pred adversaryWins { canEnumerateMaps or targetProbed or timingObservable }

assert A1_NoExhaustiveScan { verifierAccepts implies (some a: Addr | a not in probedAddrs) }
assert A3_GateBlocksEnum { gateArmed implies not canEnumerateMaps }

check A1_NoExhaustiveScan for 8 but 3 ProbeRead, 4 Block, 3 MapOp
check A3_GateBlocksEnum for 8 but 3 MapOp

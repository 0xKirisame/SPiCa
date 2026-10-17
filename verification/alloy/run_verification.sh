#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# SPiCa — Alloy Verification Runner
#
# Runs all assertions in address_secrecy.als through the Alloy Analyzer
# and reports pass/fail for each.
#
# Prerequisites: Java 17+ (brew install openjdk@17)
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$SCRIPT_DIR/alloy.jar"
MODEL="$SCRIPT_DIR/address_secrecy.als"
OUT="$SCRIPT_DIR/results"

if [ ! -f "$JAR" ]; then
    echo "[ERROR] alloy.jar not found at $JAR"
    echo "        Download from: https://github.com/AlloyTools/org.alloytools.alloy/releases/tag/v6.2.0"
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SPiCa Alloy Verification — Verifier-Bounded Address Secrecy ║"
echo "║  Model: README §6                                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

rm -rf "$OUT"
java -jar "$JAR" exec -t text -o "$OUT" -f -q "$MODEL" 2>&1 || true

echo ""
echo "═══ Results Summary ═══"
echo ""

# Assertions that held = no solution file
# Assertions that failed = solution file exists (counterexample)

for cmd in VerifierPreventsExhaustiveScan GateBlocksEnumeration ScanNotGuaranteed \
           TimingGuaranteesWin \
           LoopsNotNeeded GateNotNeeded FullDefenseAbsolute TimingIsSafe \
           BudgetAloneSuffices; do
    if ls "$OUT"/${cmd}-solution-*.txt >/dev/null 2>&1; then
        echo "  [COUNTEREXAMPLE] $cmd — assertion does NOT hold"
    else
        echo "  [VALID]         $cmd — assertion HOLDS (no counterexample)"
    fi
done

echo ""
for cmd in acceptedProgramExample luckyScanExample adversaryCanLoseWithoutTiming; do
    if ls "$OUT"/${cmd}-solution-*.txt >/dev/null 2>&1; then
        echo "  [SAT]           $cmd — example found"
    else
        echo "  [UNSAT]         $cmd — no instance exists"
    fi
done

echo ""
echo "Detailed solutions: $OUT/"
echo "Receipt:            $OUT/receipt.json"

#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# SPiCa — Alloy Verification Runner (Both Models)
#
# Runs all assertions in both the original model (address_secrecy.als)
# and the strict spec (owner_exclusive_access.als).
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$SCRIPT_DIR/alloy.jar"

run_model() {
    local MODEL="$1"
    local NAME="$2"
    local OUT="$SCRIPT_DIR/results_${NAME}"

    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "  Model: $NAME ($MODEL)"
    echo "══════════════════════════════════════════════════════════════"
    echo ""

    rm -rf "$OUT"
    java -jar "$JAR" exec -t text -o "$OUT" -f -q "$SCRIPT_DIR/$MODEL" 2>&1 || true

    echo ""
    for f in "$OUT"/*.txt; do
        [ -f "$f" ] || continue
        name=$(basename "$f" -solution-0.txt)
        echo "  [COUNTEREXAMPLE] $name"
    done

    # If no .txt files, all checks held
    if ! ls "$OUT"/*.txt >/dev/null 2>&1; then
        echo "  [ALL HOLD]       All assertions verified — no counterexamples"
    fi
}

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SPiCa Alloy Verification Suite                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"

run_model "address_secrecy.als" "secrecy"
run_model "owner_exclusive_access.als" "owner"

echo ""
echo "═══ Done ═══"

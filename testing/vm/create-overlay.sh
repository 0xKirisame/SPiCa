#!/bin/bash
# Create a qcow2 overlay from a base image for isolated testing.
# The base image is never modified — each test gets a fresh overlay.
#
# Usage: create-overlay.sh <base-image> <overlay-name>
# Example: create-overlay.sh ~/vm/ubuntu-base.qcow2 test-r2-diamorphine

set -euo pipefail

BASE="${1:?Usage: $0 <base-image.qcow2> <overlay-name>}"
NAME="${2:?Usage: $0 <base-image.qcow2> <overlay-name>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/../results/overlays"
mkdir -p "$RESULTS_DIR"

OVERLAY="$RESULTS_DIR/${NAME}.qcow2"

if [ -f "$OVERLAY" ]; then
    echo "[OVERLAY]    Reusing existing overlay: $OVERLAY"
else
    qemu-img create -f qcow2 -b "$BASE" -F qcow2 "$OVERLAY" 2>&1
    echo "[OVERLAY]    Created: $OVERLAY"
fi

echo "$OVERLAY"

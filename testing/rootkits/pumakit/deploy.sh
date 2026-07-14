#!/bin/bash
# PUMAKIT LKM rootkit — 2024 multi-stage rootkit (LKM + userland).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/../lkm-generic/lkm-test.sh" \
    pumakit \
    https://github.com/josephkingcs/pumakit \
    puma.ko

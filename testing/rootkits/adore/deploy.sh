#!/bin/bash
# Adore / Adore-NG LKM rootkit — one of the earliest Linux rootkits.
# May fail to build on 6.x kernels (designed for 2.4/2.6 era).
# Document build failure honestly for the paper.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/../lkm-generic/lkm-test.sh" \
    adore \
    https://github.com/t0r0t0r0/adore-ng \
    adore-ng.ko

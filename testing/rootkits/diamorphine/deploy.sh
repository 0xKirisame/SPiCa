#!/bin/bash
# Diamorphine LKM rootkit — process/file/module hiding via DKOM.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/../lkm-generic/lkm-test.sh" \
    diamorphine \
    https://github.com/m0nad/Diamorphine \
    diamorphine.ko

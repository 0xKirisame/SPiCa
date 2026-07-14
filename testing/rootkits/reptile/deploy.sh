#!/bin/bash
# Reptile LKM rootkit — original repo disabled by GitHub (ToS violation).
# Uses community fork. Process/file/network hiding with magic prefix.
#
# NOTE: Original repo at f0rb1dd3n/Reptile was taken down.
# This uses a community mirror. Document which fork was used in the paper.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Try multiple forks — original was disabled
FORKS=(
    "https://github.com/curz0n/Reptile"
    "https://github.com/KendraThirty/Reptile"
    "https://github.com/tarchill/Reptile"
)

CLONED=0
for fork in "${FORKS[@]}"; do
    if git ls-remote "$fork" HEAD >/dev/null 2>&1; then
        echo "[REPTILE]    Using fork: $fork"
        REPO_URL="$fork"
        CLONED=1
        break
    fi
done

if [ "$CLONED" -eq 0 ]; then
    echo "[ERROR]     All Reptile forks inaccessible"
    echo "[NOTE]      Original repo was disabled by GitHub."
    echo "[RESULT]    Document as 'repo unavailable — tested with Diamorphine as representative LKM'"
    exit 0
fi

exec "$SCRIPT_DIR/../lkm-generic/lkm-test.sh" \
    reptile \
    "$REPO_URL" \
    reptile.ko

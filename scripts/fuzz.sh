#!/usr/bin/env bash
#
# Quick fuzzing launcher
# Usage: ./scripts/fuzz.sh <target-name> [duration]
# Example: ./scripts/fuzz.sh stack-basic 60
#
set -euo pipefail

TARGET="${1:-}"
DURATION="${2:-0}"  # 0 = unlimited

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-name> [duration-seconds]"
    echo ""
    echo "Available targets:"
    ls zig-out/bin/ 2>/dev/null || echo "  (none — run 'zig build' first)"
    exit 1
fi

BINARY="./zig-out/bin/${TARGET}"

if [ ! -f "$BINARY" ]; then
    echo "[-] Binary not found: $BINARY"
    echo "[-] Run 'zig build' first."
    exit 1
fi

# Create fuzzing directories
CORPUS_DIR="fuzzing/corpus/${TARGET}"
CRASH_DIR="fuzzing/crashes/${TARGET}"
mkdir -p "$CORPUS_DIR" "$CRASH_DIR"

# Create seed input if corpus is empty
if [ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]; then
    echo "AAAA" > "${CORPUS_DIR}/seed_01"
    python3 -c "print('A'*64)" > "${CORPUS_DIR}/seed_02"
    python3 -c "print('A'*128)" > "${CORPUS_DIR}/seed_03"
    echo "[*] Created seed corpus in $CORPUS_DIR"
fi

echo "=== Fuzzing: $TARGET ==="
echo "Binary:  $BINARY"
echo "Corpus:  $CORPUS_DIR"
echo "Crashes: $CRASH_DIR"
echo ""

# Check for AFL++
if command -v afl-fuzz &>/dev/null; then
    echo "[*] Using AFL++"
    FUZZ_CMD="afl-fuzz -i $CORPUS_DIR -o $CRASH_DIR"
    if [ "$DURATION" -gt 0 ] 2>/dev/null; then
        FUZZ_CMD="$FUZZ_CMD -V $DURATION"
    fi
    FUZZ_CMD="$FUZZ_CMD -- $BINARY"
    echo "[*] $FUZZ_CMD"
    echo ""
    exec $FUZZ_CMD
else
    echo "[-] AFL++ not found. Install with: sudo apt install afl++"
    echo "[-] Or manually fuzz:"
    echo ""
    echo "    for i in \$(seq 1 1000); do"
    echo "      python3 -c \"import os; os.write(1, os.urandom(\$i))\" | timeout 1 $BINARY 2>/dev/null"
    echo "      if [ \$? -gt 128 ]; then echo \"CRASH at size \$i\"; fi"
    echo "    done"
    exit 1
fi

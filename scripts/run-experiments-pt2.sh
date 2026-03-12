#!/usr/bin/env bash
# Continue experiments from Phase 4.3 onward
set -uo pipefail

cd ~/zdvuln || exit 1
BIN=./zig-out/bin

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

sep() { echo -e "\n${CYAN}════════════════════════════════════════════════════════════${NC}"; }
header() { echo -e "${BOLD}${GREEN}$1${NC}"; }

sep
header "PHASE 4 (continued): LOGIC, TYPE, AND ARITHMETIC BUGS"
sep

echo -e "\n${YELLOW}4.3 type-confusion${NC} — Tagged union type corruption"
echo "Input: '2' (interpret variant as INTEGER)"
echo '2' | timeout 2 $BIN/type-confusion 2>&1 || true
echo "Exit code: $?"

sep
echo -e "\n${YELLOW}4.4 signedness-bug${NC} — Signed/unsigned confusion"
echo "Input: '-1' (negative int passes bounds check, wraps to huge size_t)"
echo '-1' | timeout 2 $BIN/signedness-bug 2>&1 || true
echo "Exit code: $?"

sep
echo -e "\n${YELLOW}4.5 uninitialized${NC} — Reading residual stack data"
echo "Running: leaks secrets from uninitialized stack memory"
timeout 2 $BIN/uninitialized 2>&1 || true
echo "Exit code: $?"

# ============================================================
# PHASE 5: IMAGE PARSER
# ============================================================
sep
header "PHASE 5: FILE FORMAT PARSER EXPLOITATION"
sep

echo -e "\n${YELLOW}5.1 zdf-craft valid${NC} — Create valid 10x10 ZDF image"
$BIN/zdf-craft valid 10 10 4 -o /tmp/zdvuln_valid.zdf 2>&1 || true

echo -e "\n${YELLOW}5.2 image-parser (valid)${NC} — Parse valid image"
$BIN/image-parser /tmp/zdvuln_valid.zdf 2>&1 || true

sep
echo -e "\n${YELLOW}5.3 zdf-craft overread${NC} — Create MALICIOUS image (1000x1000 header, tiny data)"
$BIN/zdf-craft overread 1000 1000 4 -o /tmp/zdvuln_evil.zdf 2>&1 || true

echo -e "\n${YELLOW}5.4 image-parser (malicious)${NC} — Parse malicious image (triggers heap over-read)"
timeout 2 $BIN/image-parser /tmp/zdvuln_evil.zdf 2>&1 || true
echo "Exit code: $?"

rm -f /tmp/zdvuln_valid.zdf /tmp/zdvuln_evil.zdf

# ============================================================
# PHASE 6: PROTOCOL PARSER (parser-server + packet-sender)
# ============================================================
sep
header "PHASE 6: PROTOCOL PARSER EXPLOITATION"
sep

echo -e "\n${YELLOW}6.1 parser-server${NC} — Starting TCP server on port 9999"
$BIN/parser-server 9999 &
SERVER_PID=$!
sleep 1

echo -e "\n${YELLOW}6.2 packet-sender (safe)${NC} — Send a normal packet"
$BIN/packet-sender 127.0.0.1 9999 1 "hello" 2>&1 || true
sleep 0.5

# Server may have crashed from previous, restart if needed
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "[*] Restarting server..."
    $BIN/parser-server 9999 &
    SERVER_PID=$!
    sleep 1
fi

echo -e "\n${YELLOW}6.3 packet-sender (overflow)${NC} — Send oversized packet (200 bytes into 128-byte buffer)"
OVERFLOW_DATA=$(python3 -c "print('A'*200)")
$BIN/packet-sender 127.0.0.1 9999 1 "$OVERFLOW_DATA" 2>&1 || true
sleep 1

# Clean up server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
echo "[*] Server stopped"

# ============================================================
# PHASE 7: RACE CONDITION
# ============================================================
sep
header "PHASE 7: RACE CONDITION (TOCTOU)"
sep

echo -e "\n${YELLOW}7.1 race-condition${NC} — Time-of-check to time-of-use"
echo "Creating /tmp/toctou_target as safe file..."
echo "This is safe content" > /tmp/toctou_target
timeout 2 $BIN/race-condition 2>&1 || true
echo "Exit code: $?"
rm -f /tmp/toctou_target

# ============================================================
# ZIG TOOLS DEMO
# ============================================================
sep
header "ZIG TOOLS DEMO"
sep

echo -e "\n${YELLOW}pattern-gen create 64${NC} — Generate 64-byte cyclic pattern"
$BIN/pattern-gen create 64 2>&1 || true

sep
echo -e "\n${YELLOW}pattern-gen find 0x41366141${NC} — Find offset in pattern"
$BIN/pattern-gen find 0x41366141 2>&1 || true

sep
echo -e "\n${YELLOW}rop-scanner${NC} — Scan stack-basic for ROP gadgets (first 50 lines)"
timeout 10 $BIN/rop-scanner $BIN/stack-basic 2>&1 | head -50 || true

sep
echo -e "\n${YELLOW}crash-analyzer${NC} — Analyze a synthetic crash sample"
python3 -c "import sys; sys.stdout.buffer.write(b'A'*64 + b'B'*8 + b'\x90'*16 + b'\xcc'*4)" > /tmp/zdvuln_crash_sample
$BIN/crash-analyzer /tmp/zdvuln_crash_sample 2>&1 || true
rm -f /tmp/zdvuln_crash_sample

# ============================================================
# SUMMARY
# ============================================================
sep
header "ALL EXPERIMENTS COMPLETE"
sep
echo ""
echo "Targets demonstrated:"
echo "  Stack:   stack-basic, stack-redirect, off-by-one"
echo "  Heap:    heap-overflow, use-after-free, double-free"
echo "  Logic:   format-string, integer-overflow, type-confusion,"
echo "           signedness-bug, uninitialized"
echo "  Parser:  image-parser (via zdf-craft)"
echo "  Network: parser-server + packet-sender"
echo "  Race:    race-condition"
echo ""
echo "Tools demonstrated: zdf-craft, pattern-gen, rop-scanner, crash-analyzer"
echo ""

#!/usr/bin/env bash
# Run all zdvuln experiments from the roadmap
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

# ============================================================
# PHASE 2: STACK CORRUPTION
# ============================================================
sep
header "PHASE 2: STACK CORRUPTION"
sep

echo -e "\n${YELLOW}2.1 stack-basic${NC} — Overflow 64-byte buffer with 200 bytes"
echo "Input: 200 x 'A' (0x41)"
python3 -c "print('A'*200)" | timeout 2 $BIN/stack-basic 2>&1 || true
echo "Exit code: $?"

sep
echo -e "\n${YELLOW}2.2 stack-redirect${NC} — Return address hijack to secret()"
echo "Input: 1024 x 'A' (attempting to overwrite return address)"
python3 -c "print('A'*1024)" | timeout 2 $BIN/stack-redirect 2>&1 || true
echo "Exit code: $?"

sep
echo -e "\n${YELLOW}2.3 off-by-one${NC} — Single byte overwrites saved RBP"
echo "Input: exactly 65 bytes (64 + 1 off-by-one)"
python3 -c "print('A'*65)" | timeout 2 $BIN/off-by-one 2>&1 || true
echo "Exit code: $?"

# ============================================================
# PHASE 3: HEAP CORRUPTION
# ============================================================
sep
header "PHASE 3: HEAP CORRUPTION"
sep

echo -e "\n${YELLOW}3.1 heap-overflow${NC} — Overflow name[64] into authenticated flag"
echo "Input: 65 x 'A' (overflows into adjacent 'authenticated' field)"
python3 -c "print('A'*65)" | timeout 2 $BIN/heap-overflow 2>&1 || true
echo "Exit code: $?"

sep
echo -e "\n${YELLOW}3.2 use-after-free${NC} — Freed struct reuse"
echo "Running: demonstrates freed memory reuse with attacker data"
timeout 2 $BIN/use-after-free 2>&1 || true
echo "Exit code: $?"

sep
echo -e "\n${YELLOW}3.3 double-free${NC} — Free-list corruption"
echo "Running: shows overlapping allocations via double-free"
timeout 2 $BIN/double-free 2>&1 || true
echo "Exit code: $?"

# ============================================================
# PHASE 4: LOGIC / TYPE / ARITHMETIC BUGS
# ============================================================
sep
header "PHASE 4: LOGIC, TYPE, AND ARITHMETIC BUGS"
sep

echo -e "\n${YELLOW}4.1 format-string${NC} — printf(buffer) info leak"
echo "Input: '%x.%x.%x.%x.%x.%x.%x.%x' (stack leak via format specifiers)"
echo '%x.%x.%x.%x.%x.%x.%x.%x' | timeout 2 $BIN/format-string 2>&1 || true
echo "Exit code: $?"

sep
echo -e "\n${YELLOW}4.2 integer-overflow${NC} — 32-bit arithmetic wrap"
echo "Input: '4' (safe input to demonstrate the program)"
echo '4' | timeout 2 $BIN/integer-overflow 2>&1 || true
echo "Exit code: $?"

sep
echo -e "\n${YELLOW}4.3 type-confusion${NC} — Tagged union type corruption"
echo "Running: shows pointer-as-integer and integer-as-pointer confusion"
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

echo -e "\n${YELLOW}5.1 zdf-craft${NC} — Create valid ZDF image"
$BIN/zdf-craft valid 10 10 4 -o /tmp/zdvuln_valid.zdf 2>&1 || true
echo ""

echo -e "\n${YELLOW}5.2 image-parser${NC} — Parse valid image"
$BIN/image-parser /tmp/zdvuln_valid.zdf 2>&1 || true
echo ""

echo -e "\n${YELLOW}5.3 zdf-craft${NC} — Create MALICIOUS image (overread: 1000x1000 header, tiny data)"
$BIN/zdf-craft overread 1000 1000 4 -o /tmp/zdvuln_evil.zdf 2>&1 || true
echo ""

echo -e "\n${YELLOW}5.4 image-parser${NC} — Parse malicious image (triggers heap over-read)"
timeout 2 $BIN/image-parser /tmp/zdvuln_evil.zdf 2>&1 || true
echo "Exit code: $?"

rm -f /tmp/zdvuln_valid.zdf /tmp/zdvuln_evil.zdf

# ============================================================
# PHASE 7: RACE CONDITION
# ============================================================
sep
header "PHASE 7: RACE CONDITION (TOCTOU)"
sep

echo -e "\n${YELLOW}7.1 race-condition${NC} — Time-of-check to time-of-use"
echo "Creating test file and running race condition target..."
echo "safe content" > /tmp/toctou_target
timeout 2 $BIN/race-condition 2>&1 || true
echo "Exit code: $?"
rm -f /tmp/toctou_target

# ============================================================
# ZIG TOOLS
# ============================================================
sep
header "ZIG TOOLS DEMO"
sep

echo -e "\n${YELLOW}pattern-gen create${NC} — Generate 64-byte cyclic pattern"
$BIN/pattern-gen create 64 2>&1 || true
echo ""

echo -e "\n${YELLOW}pattern-gen find${NC} — Find offset of pattern substring"
$BIN/pattern-gen find 0x41366141 2>&1 || true
echo ""

echo -e "\n${YELLOW}rop-scanner${NC} — Scan stack-basic for ROP gadgets"
timeout 10 $BIN/rop-scanner $BIN/stack-basic 2>&1 | head -60 || true
echo ""

echo -e "\n${YELLOW}crash-analyzer${NC} — Analyze a sample crash file"
python3 -c "import sys; sys.stdout.buffer.write(b'A'*64 + b'B'*8 + b'\x41\x41\x41\x41\x41\x41\x41\x41')" > /tmp/zdvuln_crash_sample
$BIN/crash-analyzer /tmp/zdvuln_crash_sample 2>&1 || true
rm -f /tmp/zdvuln_crash_sample

# ============================================================
# SUMMARY
# ============================================================
sep
header "ALL EXPERIMENTS COMPLETE"
sep
echo ""
echo "Targets demonstrated: stack-basic, stack-redirect, off-by-one,"
echo "  heap-overflow, use-after-free, double-free, format-string,"
echo "  integer-overflow, type-confusion, signedness-bug, uninitialized,"
echo "  image-parser, race-condition"
echo ""
echo "Tools demonstrated: zdf-craft, pattern-gen, rop-scanner, crash-analyzer"
echo ""
echo "Skipped: parser-server (requires interactive TCP server + client)"
echo "  Use: $BIN/parser-server 9999 &"
echo "  Then: $BIN/packet-sender 127.0.0.1 9999 1 hello"
echo ""

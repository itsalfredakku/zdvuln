#!/usr/bin/env bash
#
# Research Lab Setup Script
# Run inside a fresh Ubuntu 22.04 VM.
#
set -euo pipefail

echo "=== Research Lab Setup ==="
echo ""

# --- System packages ---
echo "[1/5] Installing system packages..."
sudo apt update -qq
sudo apt install -y -qq \
    gdb \
    git \
    python3 \
    python3-pip \
    curl \
    wget \
    xz-utils \
    checksec \
    netcat-openbsd \
    2>/dev/null

# --- Zig ---
echo "[2/5] Installing Zig..."
ZIG_VERSION="0.13.0"
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ZIG_ARCH="x86_64" ;;
    aarch64) ZIG_ARCH="aarch64" ;;
    *)       echo "  Unsupported architecture: $ARCH"; exit 1 ;;
esac
ZIG_ARCHIVE="zig-linux-${ZIG_ARCH}-${ZIG_VERSION}.tar.xz"
ZIG_URL="https://ziglang.org/download/${ZIG_VERSION}/${ZIG_ARCHIVE}"

if command -v zig &>/dev/null; then
    echo "  Zig already installed: $(zig version)"
else
    cd /tmp
    if [ ! -f "$ZIG_ARCHIVE" ]; then
        wget -q "$ZIG_URL"
    fi
    sudo tar -xf "$ZIG_ARCHIVE" -C /opt/
    sudo ln -sf "/opt/zig-linux-${ZIG_ARCH}-${ZIG_VERSION}/zig" /usr/local/bin/zig
    echo "  Installed: $(zig version)"
fi

# --- pwndbg ---
echo "[3/5] Installing pwndbg..."
if [ -d "$HOME/pwndbg" ]; then
    echo "  pwndbg already installed."
else
    cd "$HOME"
    git clone --quiet https://github.com/pwndbg/pwndbg
    cd pwndbg
    ./setup.sh
fi

# --- AFL++ (optional, for fuzzing) ---
echo "[4/5] Installing AFL++ (optional)..."
if command -v afl-fuzz &>/dev/null; then
    echo "  AFL++ already installed."
else
    sudo apt install -y -qq afl++ 2>/dev/null || {
        echo "  AFL++ not in apt, install manually from https://github.com/AFLplusplus/AFLplusplus"
    }
fi

# --- Ghidra (optional, for reverse engineering) ---
echo "[5/5] Ghidra..."
if command -v ghidra &>/dev/null || [ -d "/opt/ghidra" ]; then
    echo "  Ghidra already installed."
else
    echo "  Ghidra requires manual install:"
    echo "  https://ghidra-sre.org/"
    echo "  Download, extract to /opt/ghidra, add to PATH."
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  cd $(dirname "$(realpath "$0")")/.."
echo "  zig build                          # build all targets"
echo "  ./zig-out/bin/stack-basic           # run a target"
echo "  gdb ./zig-out/bin/stack-basic       # debug a target"
echo ""

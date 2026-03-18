# Zero-Day Vulnerability Research 

A hands-on lab for learning memory corruption vulnerabilities from the inside out — stack overflows, heap exploits, format strings, parser bugs, race conditions, and more. Includes 14 intentionally vulnerable C programs, a Zig-native exploit toolkit, and a guided roadmap from first crash to ROP chains.

Everything builds with a single `zig build`. No Makefiles, no cmake, no autotools.

## Requirements

| | Minimum |
|-|---------|
| **OS** | Ubuntu 22.04 (isolated VM) |
| **RAM** | 8 GB |
| **CPU** | 4 cores |

## Getting Started

```bash
./scripts/setup-lab.sh                    # install Zig, GDB, pwndbg, AFL++
zig build                                 # build everything
zig build -Dno-canary=true -Dno-pie=true  # disable mitigations for study
```

Binaries land in `zig-out/bin/`. Follow `guides/roadmap.md` for the full learning path.

## Targets

14 vulnerable C programs organized by bug class:

### Stack

| Binary | Vulnerability |
|--------|---------------|
| `stack-basic` | Buffer overflow — 256-byte read into 64-byte buffer |
| `stack-redirect` | Return address hijack via `gets()` → jump to `secret()` |
| `off-by-one` | Single byte overwrites saved RBP, hijacks control one return later |

### Heap

| Binary | Vulnerability |
|--------|---------------|
| `heap-overflow` | Overflow `name[64]` into adjacent `authenticated` flag |
| `use-after-free` | Freed struct memory reused with attacker-controlled data |
| `double-free` | Free-list corruption creates overlapping allocations |

### Logic

| Binary | Vulnerability |
|--------|---------------|
| `format-string` | `printf(buffer)` gives read/write primitives via `%x`/`%n` |
| `integer-overflow` | `num_elements * 8` wraps on 32-bit, allocates tiny buffer |
| `type-confusion` | Corrupted type tag reinterprets union data — leaks or arbitrary access |
| `signedness-bug` | Negative `int` passes bounds check, wraps to huge `size_t` in `memcpy` |
| `uninitialized` | Reads residual stack data — leaks secrets and addresses |

### Parser

| Binary | Vulnerability |
|--------|---------------|
| `parser-server` | Unvalidated length field in `[TYPE][LENGTH][DATA]` TCP protocol |
| `image-parser` | Crafted image with inflated dimensions causes heap over-read |

### Concurrency

| Binary | Vulnerability |
|--------|---------------|
| `race-condition` | TOCTOU — file swapped between safety check and use |

> Source files live in `targets/<category>/`. Each binary name maps to its `.c` file
> (e.g. `stack-basic` → `targets/stack/stack_basic.c`).

## Toolkit

### Zig Tools

Built alongside targets via `zig build`.

| Tool | What it does |
|------|-------------|
| `crash-analyzer` | Hex dump + byte frequency stats for crash samples |
| `packet-sender` | Crafted TCP packet generator for `parser-server` |
| `pattern-gen` | Cyclic pattern create/find (replaces `msf-pattern`) |
| `rop-scanner` | Scans ELF `.text` for `pop`/`ret`/`syscall` gadgets |
| `zdf-craft` | Generates valid and malicious ZDF images for `image-parser` |

### Exploit Scripts

Python/pwntools scripts in `exploits/<category>/`:

| Script | Target | Technique |
|--------|--------|-----------|
| `stack_redirect_exploit.py` | `stack-redirect` | Return address overwrite → `secret()` |
| `format_string_exploit.py` | `format-string` | `%p` stack leak + `%n` arbitrary write |
| `heap_overflow_exploit.py` | `heap-overflow` | Adjacent field corruption → flag flip |
| `parser_server_exploit.py` | `parser-server` | Protocol length overflow → RIP control |

### Exploit Library

`exploits/lib/exploit_utils.py` provides reusable primitives for writing new exploits:

- `ZdTarget` — binary launcher with ELF symbol resolution and GDB attach
- `leak_address` — parse hex addresses from program output
- `overflow_payload` / `field_overwrite` — build common overflow payloads
- `protocol_packet` — construct length-prefixed packets for parser targets
- `leak_stack_values` / `find_input_offset` — format string info leak helpers
- `find_rip_offset` — cyclic pattern-based RIP offset detection

## Usage Examples

```bash
# run a target
./zig-out/bin/stack-basic

# debug under GDB
gdb ./zig-out/bin/stack-basic

# find crash offset with cyclic pattern
./zig-out/bin/pattern-gen create 256 | ./zig-out/bin/stack-basic
./zig-out/bin/pattern-gen find 0x41366141

# scan for ROP gadgets
./zig-out/bin/rop-scanner zig-out/bin/stack-redirect --filter "pop rdi"

# craft a malicious image and test the parser
./zig-out/bin/zdf-craft overread 1000 1000 4 -o evil.zdf
./zig-out/bin/image-parser evil.zdf

# fuzz a target with AFL++ (uses per-target seed corpus)
./scripts/fuzz.sh stack-basic

# analyze a crash
./zig-out/bin/crash-analyzer fuzzing/crashes/crash_001

# run an exploit (requires pwntools)
python3 exploits/stack/stack_redirect_exploit.py

# run all integration tests
./scripts/test-all.sh
```

## Guides

| Guide | Topic |
|-------|-------|
| `guides/roadmap.md` | Progressive learning path — Phases 1 through 11 |
| `guides/memory-layout.md` | x86-64 process memory, stack frames, heap internals |
| `guides/debugging.md` | GDB/pwndbg workflows for each target |
| `guides/crash-triage.md` | Crash classification and exploitability assessment |
| `guides/mitigations.md` | Canary, NX, ASLR, PIE, RELRO — how they work, how to bypass |

## Testing

```bash
./scripts/test-all.sh
```

Runs a full integration check: build verification, binary existence, target smoke tests, tool smoke tests, and exploit validation (requires pwntools).

## Fuzzing

Pre-built seed corpus is included per target in `fuzzing/corpus/<target>/`. Each seed directory contains inputs tailored to the specific vulnerability — boundary-length strings, format specifiers, negative values, etc.

```bash
./scripts/fuzz.sh stack-basic        # uses fuzzing/corpus/stack-basic/ as seed
./scripts/fuzz.sh format-string 120  # 2-minute run with format string seeds
```

## Project Structure

```
targets/          Vulnerable C programs, by category
tools/            Zig analysis and exploit dev tools
exploits/         Python/pwntools exploit scripts, by category
exploits/lib/     Reusable exploit primitives (exploit_utils.py)
fuzzing/          AFL++ seed corpus (per-target) and crash outputs
guides/           Technical reference and learning roadmap
scripts/          Lab setup, fuzzing automation, and integration tests
build.zig         Unified build system
```

## Why Zig?

`zig cc` is a drop-in C compiler — all 14 targets compile with zero friction. `zig build` replaces Make with a single declarative build file that handles C targets and native Zig tools together. Mitigation flags (`-Dno-canary`, `-Dno-pie`) are first-class build options. Cross-compilation to ARM/MIPS is trivial when you're ready for it.

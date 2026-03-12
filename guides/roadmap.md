# Zero-Day Vulnerability Research Lab — Roadmap

Progressive learning path for memory corruption research. Each phase builds on the previous one.

**Prerequisites:** Ubuntu 22.04 VM, isolated from host. Run `./scripts/setup-lab.sh` to install all tools.

| Resource | Minimum |
|----------|---------|
| OS | Ubuntu 22.04 |
| RAM | 8–16 GB |
| CPU | 4 cores |

---

## Phase 1: Environment and Foundations

### 1.1 Set Up the Lab

```bash
./scripts/setup-lab.sh   # installs Zig, GDB, pwndbg, AFL++
zig build                 # builds all targets and tools
```

Verify the build produces binaries in `zig-out/bin/`:

```
stack-basic, stack-redirect, off-by-one
heap-overflow, use-after-free, double-free
format-string, integer-overflow, type-confusion, signedness-bug, uninitialized
parser-server, image-parser
race-condition
crash-analyzer, packet-sender
```

### 1.2 Understand Process Memory

Before exploiting anything, internalize the x86-64 Linux memory layout — where the stack, heap, and code live, how stack frames work, and what ASLR does to addresses.

**Reference:** [guides/memory-layout.md](guides/memory-layout.md)

Key exercise: compile `stack-basic` and print its buffer address 10 times with ASLR on vs. off to see randomization in action.

---

## Phase 2: Stack Corruption

### 2.1 Basic Stack Overflow

**Target:** `./zig-out/bin/stack-basic` ([targets/stack/stack_basic.c](targets/stack/stack_basic.c))

This program reads 256 bytes into a 64-byte stack buffer via `fgets()`. Overflowing the buffer overwrites the saved return address, hijacking control flow on function return.

```bash
python3 -c "print('A'*200)" | ./zig-out/bin/stack-basic
```

Under GDB, confirm RIP is overwritten with `0x4141414141414141`.

### 2.2 Return Address Redirection

**Target:** `./zig-out/bin/stack-redirect` ([targets/stack/stack_redirect.c](targets/stack/stack_redirect.c))

Same overflow, but includes a hidden `secret()` function. The program prints the buffer address and `secret()` address — calculate the offset between the buffer and the return address, then craft input to redirect execution into `secret()`.

```bash
gdb ./zig-out/bin/stack-redirect
(gdb) run
# note buffer and secret() addresses, calculate offset
```

### 2.3 Off-by-One

**Target:** `./zig-out/bin/off-by-one` ([targets/stack/off_by_one.c](targets/stack/off_by_one.c))

The most subtle stack bug. A loop uses `<=` instead of `<`, writing exactly ONE byte past a 64-byte buffer. That single byte overwrites the least significant byte of the saved frame pointer (RBP). The corruption doesn't crash immediately — it shifts the caller's stack frame, and control flow hijack happens on the **next** function return.

```bash
# Provide exactly 64 bytes of input to trigger the off-by-one
python3 -c "print('A'*64)" | ./zig-out/bin/off-by-one
```

Under GDB, set a breakpoint at the `ret` instruction in both `read_input()` and `main()`. In `read_input()`, RBP's LSB is corrupted. In `main()`, the return loads RIP from the shifted frame.

This is fundamentally harder to detect than `stack-basic` because the overflow is a single byte, and the crash happens in a different function than the one with the bug.

---

## Phase 3: Heap Corruption

### 3.1 Heap Buffer Overflow

**Target:** `./zig-out/bin/heap-overflow` ([targets/heap/heap_overflow.c](targets/heap/heap_overflow.c))

Allocates a struct with `name[64]` followed by `authenticated`. Reading 200 bytes into `name` overflows into the adjacent `authenticated` field, flipping it from 0 to a nonzero value.

```bash
python3 -c "print('A'*65)" | ./zig-out/bin/heap-overflow
```

Under GDB, use `x/16x <address>` to inspect the struct layout before and after overflow.

### 3.2 Use-After-Free

**Target:** `./zig-out/bin/use-after-free` ([targets/heap/use_after_free.c](targets/heap/use_after_free.c))

Allocates an `admin` struct (privilege level 9999), frees it, then allocates new user-controlled data. Because the allocator reuses the freed memory, the old `admin` pointer now reads attacker-controlled data.

```bash
gdb ./zig-out/bin/use-after-free
(gdb) break main
(gdb) run
# step through malloc → free → second malloc, watch the address reuse
```

**Reference:** [guides/debugging.md](guides/debugging.md) — heap bug analysis workflow

### 3.3 Double-Free

**Target:** `./zig-out/bin/double-free` ([targets/heap/double_free.c](targets/heap/double_free.c))

Distinct from use-after-free — this corrupts the allocator's free list by freeing the same chunk twice. After the double-free, two subsequent `malloc()` calls return the same address, creating **overlapping allocations**. Writing through one overwrites the other.

```bash
./zig-out/bin/double-free
```

The program walks through the attack step by step: allocate → free → free again (with an intermediate free to bypass glibc's fastbin duplicate check) → three mallocs → first and third alias the same memory. Under GDB, set breakpoints at each `free()` and `malloc()` to watch the free list corruption.

This is the technique used in Pegasus heap exploits: double-free → overlapping allocation → overwrite a live object's function pointer or privilege field.

---

## Phase 4: Logic, Type, and Arithmetic Bugs

These bugs aren't about overflowing a buffer — they exploit flaws in program logic, type handling, or arithmetic. Moved out of `stack/` and `heap/` because the bug is in the **logic**, not the memory region.

### 4.1 Format String Exploitation

**Target:** `./zig-out/bin/format-string` ([targets/logic/format_string.c](targets/logic/format_string.c))

User input is passed directly to `printf(buffer)`. This is an API misuse bug — `printf` treats the input as a format specifier, not data:

- **Read:** `%x.%x.%x.%x` walks the stack, leaking values (including `secret_value = 0x41414141`)
- **Write:** `%n` writes the number of bytes printed to an address on the stack

```bash
echo '%x.%x.%x.%x.%x.%x' | ./zig-out/bin/format-string
```

### 4.2 Integer Overflow

**Target:** `./zig-out/bin/integer-overflow` ([targets/logic/integer_overflow.c](targets/logic/integer_overflow.c))

User supplies `num_elements`. The program computes `total_size = num_elements * 8` using 32-bit arithmetic. With `num_elements = 0x40000001`:

```
0x40000001 * 8 = 0x200000008 → wraps to 0x00000008 (32-bit)
```

Result: `malloc(8)` allocates 8 bytes, but the program expects space for `0x40000001 * 8` bytes — a massive heap overflow.

### 4.3 Type Confusion

**Target:** `./zig-out/bin/type-confusion` ([targets/logic/type_confusion.c](targets/logic/type_confusion.c))

A tagged union (`struct variant`) stores strings, integers, or buffers — dispatching on a `type` field. If an attacker corrupts the type tag (via adjacent overflow, UAF, or double-free), the union data is interpreted using the wrong type:

- **Pointer → Integer**: a heap pointer is printed as an integer — **address leak** (ASLR bypass)
- **Integer → Pointer**: an attacker-controlled integer is dereferenced as a pointer — **arbitrary read/write**

```bash
./zig-out/bin/type-confusion
```

This mirrors type confusion bugs in JavaScript engines (V8, SpiderMonkey), media codecs, and serialization frameworks.

### 4.4 Signedness Bug

**Target:** `./zig-out/bin/signedness-bug` ([targets/logic/signedness_bug.c](targets/logic/signedness_bug.c))

Different from integer overflow — this exploits signed/unsigned confusion. A negative signed integer passes a bounds check (`-1 < 256` is true), then is cast to `size_t` for `memcpy` — becoming `0xFFFFFFFFFFFFFFFF` (18 exabytes).

```bash
./zig-out/bin/signedness-bug
# try entering -1 when prompted
```

This pattern appears in the Linux kernel (CVE-2018-14634), network parsers that read length fields as signed, and libc functions that mix `int` and `size_t`.

### 4.5 Uninitialized Memory

**Target:** `./zig-out/bin/uninitialized` ([targets/logic/uninitialized.c](targets/logic/uninitialized.c))

No write needed — the attacker just reads what's already on the stack. A function leaves sensitive data (keys, tokens, addresses) in its stack frame. The next function allocates a buffer in the same stack space without initializing it, and reads the residual data.

```bash
./zig-out/bin/uninitialized
```

This is exactly how **Heartbleed** (CVE-2014-0160) worked — uninitialized heap memory leaked private keys and session credentials. The fix is simple: always initialize (`memset`, `= {0}`, `calloc`).

---

## Phase 5: File Format Parser Exploitation

**Target:** `./zig-out/bin/image-parser` ([targets/parser/image_parser.c](targets/parser/image_parser.c))

A minimal image format parser ("ZDF" format: `[MAGIC:4][WIDTH:4][HEIGHT:4][BPP:1][PIXELS...]`). The vulnerability: `process_pixels()` allocates a buffer based on the **declared** dimensions from the header, then copies that many bytes from the **actual** pixel data — which may be far smaller.

A crafted file with `width=1000, height=1000, bpp=4` but only 16 bytes of pixel data causes a heap over-read of ~4 million bytes.

```bash
# Create a malicious ZDF file: valid header, inflated dimensions, tiny data
python3 -c "
import struct
header = b'ZDF\x00'
header += struct.pack('<I', 1000)   # width
header += struct.pack('<I', 1000)   # height
header += struct.pack('B', 4)       # bpp
pixels = b'\x41' * 16              # only 16 bytes of actual data
with open('evil.zdf', 'wb') as f:
    f.write(header + pixels)
" 

./zig-out/bin/image-parser evil.zdf
```

This mirrors the class of exploit that powered **FORCEDENTRY** (CVE-2021-30860) — a crafted JBIG2 image with malformed segment lengths, delivered via iMessage with zero user interaction. The same pattern appears in libpng, libjpeg, libwebp, and PDF parser vulnerabilities.

**Key difference from `parser-server`:** file-based input vs. network input. File format parsers are the #1 zero-click remote attack surface because they process untrusted data automatically (image previews, message attachments, document thumbnails).

---

## Phase 6: Protocol Parser Exploitation

### 6.1 Run the Parser Server

**Target:** `./zig-out/bin/parser-server` ([targets/parser/parser_server.c](targets/parser/parser_server.c))

A TCP server parsing `[TYPE:1][LENGTH:2][DATA:LENGTH]` packets. The vulnerability: `handle_packet()` copies `hdr.length` bytes into a 128-byte stack buffer via `memcpy()` without validating the length.

```bash
# Terminal 1: start the server
./zig-out/bin/parser-server 9999

# Terminal 2: send a normal packet
./zig-out/bin/packet-sender 127.0.0.1 9999 1 "hello"

# Terminal 3: trigger the overflow
./zig-out/bin/packet-sender 127.0.0.1 9999 1 $(python3 -c "print('A'*200)")
```

### 6.2 Debug the Parser Crash

```bash
gdb ./zig-out/bin/parser-server
(gdb) run 9999
# send overflow packet from another terminal
(gdb) info registers    # check RIP
(gdb) bt                # backtrace into handle_packet
```

This pattern — trusting a client-supplied length field — appears in real-world VoIP stacks, IoT firmware, messaging protocols, and media parsers.

**Reference:** [guides/debugging.md](guides/debugging.md) — parser server analysis workflow

---

## Phase 7: Race Conditions

**Target:** `./zig-out/bin/race-condition` ([targets/concurrency/race_condition.c](targets/concurrency/race_condition.c))

Completely different attack model — no memory corruption at all. The program checks if a file is safe (regular file, owned by current user), then reads it. Between the check and the read, an attacker replaces the file with a symlink to `/etc/passwd` or any sensitive file.

```bash
# Terminal 1: run the target
./zig-out/bin/race-condition

# Terminal 2: race the file swap
while true; do
  ln -sf /etc/passwd /tmp/toctou_target 2>/dev/null
  ln -sf /tmp/safe_backup.txt /tmp/toctou_target 2>/dev/null
done
```

This is how privilege escalation works in real systems — setuid programs checking file permissions, then opening the file. The gap between `lstat()` and `fopen()` is the TOCTOU window.

**The fix:** open the file FIRST, then `fstat()` the file descriptor. The fd always refers to the same inode, even if the path changes.

---

## Phase 8: Mitigations

Study how modern defenses prevent exploitation, then selectively disable them to understand each one:

```bash
# All mitigations off (easiest to exploit)
zig build -Dno-canary=true -Dno-pie=true

# Default build (canary and PIE disabled for study)
zig build

# Check what's enabled on a binary
checksec ./zig-out/bin/stack-basic
```

| Mitigation | What It Prevents | How to Bypass |
|------------|-----------------|---------------|
| Stack Canary | Return address overwrite | Leak canary via format string |
| NX / DEP | Shellcode on stack/heap | Return-Oriented Programming (ROP) |
| ASLR | Predictable addresses | Information leak |
| PIE | Known code addresses | Info leak + ASLR bypass |
| Full RELRO | GOT overwrite | Alternative write target |

**Reference:** [guides/mitigations.md](guides/mitigations.md) — full details, compile flags, and bypass techniques

---

## Phase 9: Fuzzing

### 9.1 Automated Fuzzing

Use AFL++ to discover crashes automatically:

```bash
./scripts/fuzz.sh stack-basic        # fuzzes with auto-seeded corpus
./scripts/fuzz.sh stack-basic 3600   # fuzz for 1 hour
```

Crashes are saved to `fuzzing/crashes/`. The script seeds an empty corpus with `"AAAA"`, 64x`A`, and 128x`A`.

### 9.2 Crash Analysis

Analyze crash samples with the Zig crash analyzer:

```bash
./zig-out/bin/crash-analyzer fuzzing/crashes/crash_001
```

This produces a hex/ASCII dump and counts printable bytes, NULLs, `0x41` patterns, and NOP slides (`0x90`).

**Reference:** [guides/crash-triage.md](guides/crash-triage.md) — crash classification, exploitability assessment, and documentation template

---

## Phase 10: Reverse Engineering (Beyond This Lab)

When source code is unavailable, use disassemblers to recover program logic:

| Tool | Use Case |
|------|----------|
| Ghidra | Full decompiler, free, supports most architectures |
| radare2 | CLI-based disassembly and analysis |
| objdump / readelf | Quick inspection (shipped with Zig) |

Patterns to look for in disassembly:
- `memcpy` / `strcpy` without bounds checking
- `malloc` followed by unchecked size calculations
- Format strings with user-controlled arguments
- Signed/unsigned confusion in size calculations
- TOCTOU patterns: check-then-act on file paths

---

## Phase 11: Applying This Knowledge

This lab builds foundations directly applicable to securing:

- **Network protocols** — parser bugs are the #1 remote attack surface
- **Messaging systems** — buffer handling in serialization/deserialization
- **Distributed infrastructure** — memory safety in high-throughput data paths
- **Device firmware** — constrained environments where mitigations are often absent

The progression: understand the bug → understand the defense → build software that doesn't have the bug.

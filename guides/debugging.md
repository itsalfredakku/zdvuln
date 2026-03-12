# Debugging Workflow

GDB workflows for analyzing each target in this lab. All examples assume binaries are built with `zig build`.

## Setup

Use GDB with [pwndbg](https://github.com/pwndbg/pwndbg) for enhanced memory visualization:

```bash
# Load a target into GDB
gdb ./zig-out/bin/stack-basic

# Or with GEF instead
gdb -ex 'source ~/.gdbinit-gef.py' ./zig-out/bin/stack-basic
```

## Core GDB Commands

### Execution Control

```
run                    # start program
run < input.txt        # start with file input
break main             # breakpoint at function
break *0x401234        # breakpoint at address
continue               # resume after breakpoint
stepi                  # single instruction step
nexti                  # step over calls
finish                 # run until function returns
```

### Inspection

```
info registers         # all register values
print $rip             # instruction pointer
print $rsp             # stack pointer
print $rbp             # base pointer

x/32x $rsp             # 32 hex words at stack pointer
x/16s $rsp             # 16 strings at stack pointer
x/10i $rip             # 10 instructions at current IP

disassemble            # current function
disassemble main       # specific function
```

### Memory Examination Format

```
x/FMT ADDRESS

Count: number of units
Format: x=hex, d=decimal, s=string, i=instruction, c=char
Size: b=byte, h=halfword(2), w=word(4), g=giant(8)

Examples:
  x/32xw $rsp          # 32 hex words from stack
  x/100xb $rax         # 100 hex bytes from rax
  x/10i $rip           # 10 instructions from rip
  x/s $rdi             # string at rdi
```

### Crash Analysis

```
bt                     # backtrace (call stack)
bt full                # backtrace with local variables
info frame             # current stack frame details
info proc mappings     # memory map (ASLR addresses)
```

## Workflow: Stack Overflow (`stack-basic`)

```bash
# 1. Generate overflow input (200 bytes into 64-byte buffer)
python3 -c "print('A'*200)" > crash_input.txt

# 2. Load into GDB
gdb ./zig-out/bin/stack-basic
(gdb) run < crash_input.txt

# 3. On crash — confirm RIP is attacker-controlled
(gdb) info registers          # RIP = 0x4141414141414141 = success
(gdb) x/32x $rsp              # inspect stack contents
(gdb) bt                      # backtrace shows crash location

# 4. Find the exact offset to RIP using a cyclic pattern
python3 -c "
import sys
pattern = ''
for i in range(200):
    pattern += chr(0x41 + (i % 26))
sys.stdout.write(pattern)
" > pattern_input.txt

# 5. With pwndbg — the offset is shown automatically
(gdb) run < pattern_input.txt
```

## Workflow: Heap Use-After-Free (`use-after-free`)

```bash
gdb ./zig-out/bin/use-after-free

# Set breakpoint and step through allocations
(gdb) break main
(gdb) run
(gdb) # step to first malloc — note the returned address
(gdb) x/16x <address>         # view struct with heap metadata
(gdb) # step past free()
(gdb) x/16x <address>         # metadata changed — chunk marked free
(gdb) # step past second malloc()
(gdb) x/16x <address>         # same address returned — attacker data now here
```

The key observation: after `free()` and a same-sized `malloc()`, the allocator returns the same address. The old pointer now reads attacker-controlled data.

## Workflow: File Format Parser (`image-parser`)

```bash
# Create a malicious ZDF file with inflated dimensions
python3 -c "
import struct
header = b'ZDF\x00' + struct.pack('<I', 500) + struct.pack('<I', 500) + struct.pack('B', 4)
with open('evil.zdf', 'wb') as f:
    f.write(header + b'\x41' * 16)
"

gdb ./zig-out/bin/image-parser
(gdb) run evil.zdf
# Crash in process_pixels() — memcpy reads past the 16-byte pixel buffer
(gdb) bt                      # backtrace shows crash in process_pixels
(gdb) info registers          # check what address caused the fault
```

The overflow occurs because `process_pixels()` trusts the header's declared dimensions (500×500×4 = 1,000,000 bytes) but only 16 bytes of pixel data exist. The `memcpy` reads 999,984 bytes past the end of the file buffer.

## Workflow: Double-Free (`double-free`)

```bash
gdb ./zig-out/bin/double-free

(gdb) break main
(gdb) run
# Step through and watch the free list corruption:
# 1. After first free(s1): s1 is on the free list
# 2. After free(s2): s2 is on the free list (intermediate free)
# 3. After second free(s1): s1 is on the free list AGAIN
# 4. After three mallocs: alloc_a and alloc_c have the SAME address
(gdb) print alloc_a
(gdb) print alloc_c           # same address as alloc_a
```

The critical moment: after the double-free, `malloc()` returns the same address twice. Writing through one allocation corrupts the other.

## Workflow: Type Confusion (`type-confusion`)

```bash
gdb ./zig-out/bin/type-confusion

(gdb) break main
(gdb) run
# Step to where v1 is created as STRING
(gdb) print v1->type           # 1 (TYPE_STRING)
(gdb) print v1->str_val        # heap pointer
# Step to where v1->type is changed to TYPE_INTEGER
(gdb) print v1->int_val        # same bits, now interpreted as integer = heap address leaked
```

Observe how the same union bytes are interpreted completely differently depending on the type tag — this is the foundation of type confusion exploits in JS engines and media codecs.

## Workflow: Off-by-One (`off-by-one`)

```bash
gdb ./zig-out/bin/off-by-one

(gdb) disassemble read_input   # find the 'ret' instruction address
(gdb) break *<ret_addr>        # break at read_input's return
(gdb) run
# Type exactly 64 'A' characters

(gdb) info registers           # check RBP — LSB should be 0x41 (corrupted)
(gdb) continue                 # continue to main's return
# Crash — main loads return address from wrong location due to shifted RBP
```

The off-by-one is invisible at the point of the overflow. The crash happens one return later, in a different function — making it much harder to trace back to the root cause.

## Workflow: Signedness Bug (`signedness-bug`)

```bash
gdb ./zig-out/bin/signedness-bug

(gdb) break process_data
(gdb) run
# Enter -1 when prompted

(gdb) print length             # -1 (signed)
(gdb) print (size_t)length     # 0xFFFFFFFFFFFFFFFF (unsigned)
# The bounds check (length < 256) passes because -1 < 256 is true
# But memcpy receives 18 exabytes as the size → SIGSEGV
```

## Workflow: Uninitialized Memory (`uninitialized`)

```bash
gdb ./zig-out/bin/uninitialized

(gdb) break read_uninitialized
(gdb) run
# After load_secret() returns, step into read_uninitialized()

(gdb) x/16x $rbp-128          # examine the uninitialized buffer
# You'll see load_secret()'s residual data: "SECRET_KEY_0xDEAD",
# the session token (0xCAFEBABE12345678), and stack addresses
```

No overflow, no write — just reading what was already on the stack. This is a pure info leak primitive.

## Workflow: Protocol Parser (`parser-server`)

```bash
# Terminal 1 — run the server under GDB
gdb ./zig-out/bin/parser-server
(gdb) run 9999

# Terminal 2 — send an oversized packet to trigger the overflow
./zig-out/bin/packet-sender 127.0.0.1 9999 1 $(python3 -c "print('A'*200)")

# GDB catches the crash in handle_packet()
(gdb) info registers          # check if RIP is controlled
(gdb) bt                      # backtrace shows crash in handle_packet
(gdb) x/32x $rsp              # stack filled with 0x41
```

The overflow occurs because `handle_packet()` copies `hdr.length` bytes into `parse_buf[128]` via `memcpy()` without validating the length field.

## Checklist: Questions at Every Crash

1. **What register is corrupted?** — RIP = control flow hijack, RAX/RDI = data corruption
2. **Is the corrupted value attacker-controlled?** — patterns like `0x4141414141414141` confirm this
3. **What's the offset from the buffer to the target?** — determines payload structure
4. **Which mitigations are active?** — run `checksec ./zig-out/bin/<target>`
5. **What exploit primitive does this give?** — arbitrary write, control flow redirect, info leak

# Crash Triage

Systematic process for determining if a crash is exploitable. Use this after fuzzing produces crash samples or after manually triggering a crash in any lab target.

## Triage Flow

```
Crash found (fuzzer / manual)
       │
       ▼
Reproduce crash
       │
       ▼
Classify crash type
       │
       ├── SIGSEGV (segmentation fault)
       │      ├── Read access violation  → info leak potential
       │      └── Write access violation → memory corruption
       │
       ├── SIGABRT (abort)
       │      ├── Heap corruption detected by allocator
       │      └── Assertion failure
       │
       └── SIGBUS (bus error)
              └── Alignment issue
       │
       ▼
Determine attacker control
       │
       ├── Does attacker control the faulting address?
       ├── Does attacker control data being written?
       └── Does attacker control instruction pointer?
       │
       ▼
Severity assessment
```

## Crash Classification

### Exploitability Levels

| Level | Condition | Example |
|-------|-----------|---------|
| **Critical** | Attacker controls RIP | Stack overflow → return address overwrite |
| **High** | Attacker controls write target | Heap overflow → arbitrary write |
| **Medium** | Attacker controls read target | Out-of-bounds read → info leak |
| **Low** | Crash but no control | NULL deref, assertion |

### What Makes a Crash Exploitable?

```
Exploitable if attacker can:
  1. Control WHAT is written       (write primitive)
  2. Control WHERE it is written   (arbitrary address)
  3. Control execution flow        (RIP overwrite)

The combination of 1 + 2 = arbitrary write = usually exploitable.
RIP control alone = definitely exploitable.
```

## Triage Commands

```bash
# 1. Reproduce the crash against a specific target
./zig-out/bin/stack-basic < fuzzing/crashes/crash_001

# 2. Load into GDB for inspection
gdb --args ./zig-out/bin/stack-basic
(gdb) run < fuzzing/crashes/crash_001

# 3. On crash — gather state
(gdb) info registers              # check RIP, RSP, RAX
(gdb) x/i $rip                    # faulting instruction
(gdb) bt                          # call stack
(gdb) info proc mappings          # memory layout

# 4. Hex dump the crash sample
./zig-out/bin/crash-analyzer fuzzing/crashes/crash_001
```

## Pattern Recognition

### Stack overflow indicators (`stack-basic`, `stack-redirect`, `off-by-one`, `parser-server`)

```
RIP = 0x4141414141414141          # return address overwritten with attacker data
RSP points to attacker data       # stack pivot possible
"stack smashing detected"         # canary caught the overflow (build with canary enabled)
RBP LSB corrupted                 # off-by-one — crash happens on the CALLER's return
```

### Heap corruption indicators (`heap-overflow`, `double-free`)

```
"free(): invalid pointer"         # heap metadata corrupted by overflow
"double free or corruption"       # glibc detected double-free (double-free target)
"malloc(): corrupted top size"    # overflow reached heap metadata
SIGSEGV during malloc/free        # corrupted metadata pointers
Two allocations at same address   # double-free → overlapping allocations
```

### Use-after-free indicators (`use-after-free`)

```
Crash dereferences freed memory   # dangling pointer access
Same address allocated twice      # allocator returned a freed chunk
Struct fields contain unexpected  # attacker data occupies freed object
```

### Type confusion indicators (`type-confusion`)

```
Pointer interpreted as integer    # address leak — ASLR bypass primitive
Integer dereferenced as pointer   # SIGSEGV at attacker-controlled address
Wrong union member accessed       # type tag corrupted or unchecked
```

### Signedness indicators (`signedness-bug`)

```
Negative value passes bounds check  # signed comparison: -1 < MAX passes
memcpy with huge size               # (size_t)(-1) = 0xFFFFFFFFFFFFFFFF
SIGSEGV in memcpy/memmove           # tried to copy exabytes of data
```

### Uninitialized memory indicators (`uninitialized`)

```
Output contains unexpected data     # residual stack/heap data leaked
Pointer values in output            # stack addresses from previous frames
No crash, but sensitive data exposed # info leak without any overflow
```

### Format string indicators (`format-string`)

```
Crash at printf/sprintf           # %s dereferences attacker-controlled value
Register contains stack data      # %x leaked stack contents
```

## Documenting a Crash

For each crash, record:

```markdown
## Crash ID: XXXX

**File:** fuzzing/crashes/crash_001
**Target:** parser-server (targets/parser/parser_server.c)
**Signal:** SIGSEGV
**Faulting instruction:** mov [rax], rdx
**RIP:** 0x401234 (inside handle_packet)
**Attacker controls:** RAX (write target), RDX (write value)
**Root cause:** hdr.length not validated before memcpy into parse_buf[128]
**Exploitability:** Critical — arbitrary write primitive
**Mitigation bypass needed:** ASLR (requires info leak for reliable exploitation)
```

## Filing Crashes

Save all artifacts:

```
fuzzing/crashes/
  ├── crash_001           # raw crash input
  ├── crash_001.notes.md  # triage notes
  ├── crash_001.gdb.txt   # GDB session log
  └── crash_001.bt.txt    # backtrace
```

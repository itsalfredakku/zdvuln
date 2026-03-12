# Modern Mitigations

Every mitigation exists because of a specific attack technique. This guide pairs each defense with the lab target it protects against and the technique used to bypass it.

## Stack Canary

**What it does:** Places a random value between local variables and the return address. Checked before function returns.

```
┌──────────────┐
│ return addr   │
├──────────────┤
│ CANARY        │  ← random value, checked on return
├──────────────┤
│ local vars    │  ← overflow starts here
└──────────────┘
```

**How to observe it in the lab:**

```bash
# Build stack-basic without canary (overflow succeeds, RIP controlled)
zig cc -fno-stack-protector -g -o vuln targets/stack/stack_basic.c

# Build stack-basic with canary (overflow detected, program aborts)
zig cc -fstack-protector-all -g -o vuln-protected targets/stack/stack_basic.c

# Or use the build system (canary disabled by default for study)
zig build -Dno-canary=true
```

**Bypass techniques (for understanding):**
- Leak the canary value via `format-string` (`%x` walks the stack and can expose the canary)
- Brute-force canary byte-by-byte (possible in forking servers like `parser-server`)
- Overwrite a function pointer below the canary (avoids the canary check entirely)
- Use `type-confusion` to leak addresses without touching the canary at all
- `off-by-one` overwrites the saved RBP, not the canary \u2014 the canary sits between RBP and the return address, so off-by-one bypasses it entirely

---

## NX / DEP (Non-Executable Memory)

**What it does:** Marks memory regions (stack, heap) as non-executable. Injected code can't run.

**Check any lab binary:**
```bash
checksec ./zig-out/bin/stack-basic
# Look for: NX enabled
```

**Without NX:** attacker injects shellcode onto the stack via `stack-basic` overflow → jumps to it → code executes.

**With NX:** stack is non-executable — attacker must reuse existing code in the binary (Return-Oriented Programming / ROP).

---

## ASLR (Address Space Layout Randomization)

**What it does:** Randomizes base addresses of stack, heap, and libraries on every execution.

```bash
# Check current setting
cat /proc/sys/kernel/randomize_va_space
# 0 = off, 1 = partial, 2 = full

# Disable temporarily (in VM only!)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Re-enable
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

**Why it matters:** Without ASLR, the buffer address in `stack-redirect` is identical every run — the attacker knows exactly where to jump. With ASLR, an information leak is needed first.

**Bypass techniques (for understanding):**
- Information leak via `format-string` (`%x` exposes stack addresses including return pointers)
- Type confusion address leak — `type-confusion` reinterprets a heap pointer as an integer, revealing the address
- Brute-force (32-bit systems have limited entropy — ~256 attempts)
- Return-to-PLT (PLT entries are at known offsets in non-PIE binaries)

---

## PIE (Position-Independent Executable)

**What it does:** Randomizes the base address of the program's own code.

Without PIE: `stack-redirect`'s `.text` section is always at `0x400000` — the `secret()` address is fixed.
With PIE: `.text` starts at a random base on each run.

```bash
# Without PIE (easier to study — fixed addresses for stack-redirect's secret())
zig cc -fno-pie -no-pie -g -o vuln targets/stack/stack_redirect.c

# With PIE (addresses randomized)
zig cc -fPIE -pie -g -o vuln-pie targets/stack/stack_redirect.c
```

---

## RELRO (Relocation Read-Only)

**What it does:** Makes the Global Offset Table (GOT) read-only after loading.

- Partial RELRO: GOT writable (can overwrite function pointers)
- Full RELRO: GOT read-only (GOT overwrite blocked)

```bash
# Full RELRO
zig cc -Wl,-z,relro,-z,now -o program program.c
```

---

## Mitigation Matrix

| Mitigation | Protects Against | Bypass Requires |
|------------|-----------------|-----------------|
| Stack Canary | Stack buffer overflow → ret overwrite | Canary leak or function pointer overwrite |
| NX | Shellcode injection | ROP / code reuse |
| ASLR | Hardcoded addresses | Information leak |
| PIE | Known code addresses | Info leak + ASLR bypass |
| Full RELRO | GOT overwrite | Alternative write target |

## Build System Integration

The lab's `build.zig` exposes mitigation flags:

```bash
# All mitigations off (easiest to study — start here)
zig build -Dno-canary=true -Dno-pie=true

# Default build (canary and PIE already disabled for study)
zig build

# Verify what's enabled on any binary
checksec ./zig-out/bin/stack-basic
checksec ./zig-out/bin/parser-server
```

# Process Memory Layout

Every vulnerability class in this lab — stack overflows, heap corruption, use-after-free — targets a specific memory region. This guide maps out where each region lives and why overflows travel the direction they do.

## Linux x86-64 Memory Map

```
0xFFFFFFFFFFFFFFFF ┌──────────────────────┐
                   │  Kernel space         │  (inaccessible from userland)
0x7FFF............ ├──────────────────────┤
                   │  Stack                │  grows ↓
                   │  (local vars, ret     │
                   │   addresses, frames)  │
                   ├──────────────────────┤
                   │  Memory-mapped region │  shared libs, mmap()
                   ├──────────────────────┤
                   │  Heap                 │  grows ↑
                   │  (malloc/free)        │
                   ├──────────────────────┤
                   │  BSS                  │  uninitialized globals
                   ├──────────────────────┤
                   │  Data                 │  initialized globals
                   ├──────────────────────┤
                   │  Text                 │  executable code
0x0000000000400000 └──────────────────────┘
```

## Stack Frame Layout

Each function call pushes a new frame onto the stack:

```
┌─────────────────────┐  high address
│  caller's frame      │
├─────────────────────┤
│  return address      │  ← overwriting this = control flow hijack
├─────────────────────┤
│  saved base pointer  │  (RBP)
├─────────────────────┤
│  local variables     │  ← buffer overflow starts here
│  (char buffer[64])   │
├─────────────────────┤
│  ...                 │
└─────────────────────┘  low address
```

**Why stack overflow works:** Local variables (`buffer[64]`) sit below the saved return address. Writing past the buffer overwrites the return address — this is exactly what `stack-basic` and `stack-redirect` exploit. The subtler variant `off-by-one` overwrites just one byte of the saved RBP, shifting the frame pointer and crashing one return later.

## Heap Layout

```
malloc(64) → allocator finds free chunk → returns pointer
free(ptr)  → chunk marked as free → metadata updated
```

Heap metadata sits adjacent to user data. Overflowing a heap buffer corrupts:
- **Adjacent struct fields** — `heap-overflow` overflows `name[64]` into the adjacent `authenticated` field
- **Freed chunk metadata** — `use-after-free` exploits memory reuse after `free()` returns a chunk to the allocator
- **Free list integrity** — `double-free` puts the same chunk on the free list twice, causing `malloc()` to return overlapping allocations
- **Type interpretation** — `type-confusion` shows how corrupting a type tag causes a heap pointer to be read as an integer (address leak) or an integer to be dereferenced as a pointer (arbitrary access)

## Uninitialized Memory

Stack memory is NOT zeroed between function calls. When a function returns, its local variables remain on the stack. If the next function allocates a buffer in the same space without initializing it, it reads the previous function's data — this is what `uninitialized` demonstrates. The same applies to heap memory (`malloc` doesn't zero; `calloc` does).

## ASLR: Address Randomization

Without ASLR:
```
stack always at 0x7FFFFFFDE000
heap always at  0x00602000
text always at  0x00400000
```

With ASLR:
```
stack at random offset
heap at random offset
libraries at random offset
```

Check: `cat /proc/self/maps`

## Exercises

1. Run `./zig-out/bin/stack-redirect` 10 times — the printed buffer address changes each run (ASLR)
2. Disable ASLR (`echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`) and repeat — address is now fixed
3. Load `stack-basic` in GDB and run `info proc mappings` — identify stack, heap, and text regions
4. Load `use-after-free` in GDB, set a breakpoint at `main`, step through `malloc → free → malloc` and use `x/16x <address>` to watch the same address get reused
5. Re-enable ASLR when done: `echo 2 | sudo tee /proc/sys/kernel/randomize_va_space`
6. Run `uninitialized` and observe how residual stack data from one function leaks into another

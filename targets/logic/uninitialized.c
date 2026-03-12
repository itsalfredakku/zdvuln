/*
 * Uninitialized Memory Read
 *
 * Bug: a stack buffer is declared but not fully initialized. A later read
 * exposes whatever data was left on the stack from previous function calls
 * — leaking sensitive information (passwords, keys, pointers).
 *
 * This is a different primitive from all other targets:
 *   - No overflow, no corruption, no write needed
 *   - The attacker doesn't WRITE anything — they just READ what's already there
 *   - The "bug" is the ABSENCE of initialization, not the presence of a bad write
 *
 * Real-world examples:
 *   - Heartbleed (CVE-2014-0160): uninitialized heap memory leaked via TLS heartbeat
 *   - Linux kernel info leaks via uninitialized struct fields copied to userspace
 *   - Stack-based info leaks in crypto implementations exposing key material
 *
 * Study:
 *   - Why does the stack contain "garbage" from previous calls?
 *   - How can an attacker influence what data is on the stack before this function?
 *   - Why is this an ASLR bypass primitive (stack addresses leaked)?
 *
 * Build: zig build
 * Run:   ./zig-out/bin/uninitialized
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* This function puts sensitive data on the stack, then returns.
 * The data remains on the stack after the function exits. */
void load_secret(void) {
    char secret[] = "SECRET_KEY_0xDEAD";
    uint64_t session_token = 0xCAFEBABE12345678ULL;
    void *stack_ptr = &secret;

    printf("[*] load_secret() placed on stack:\n");
    printf("    secret:        \"%s\"\n", secret);
    printf("    session_token: 0x%lx\n", (unsigned long)session_token);
    printf("    stack address: %p\n\n", stack_ptr);

    /* Function returns — but the data is still on the stack */
    (void)session_token;
    (void)stack_ptr;
}

/* This function reads a stack buffer WITHOUT initializing it.
 * Because it's called right after load_secret(), the buffer
 * overlaps with load_secret's old stack frame — exposing its data. */
void read_uninitialized(void) {
    char buffer[128];  /* NOT initialized — contains whatever was on the stack */

    /*
     * BUG: buffer is never initialized (no memset, no assignment).
     * It contains residual data from load_secret()'s stack frame.
     * Printing it leaks the secret key, session token, and stack addresses.
     */
    printf("[*] read_uninitialized() — buffer NOT initialized.\n");
    printf("[*] Dumping raw stack contents (residual data):\n\n");

    /* Show raw bytes — these contain load_secret's data */
    printf("    Hex dump of uninitialized buffer:\n    ");
    for (int i = 0; i < 64; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
        if ((i + 1) % 16 == 0) printf("\n    ");
    }
    printf("\n");

    /* Try to print as string — may show the secret */
    printf("    As string: \"%.32s\"\n\n", buffer);

    /* Check if secret leaked */
    if (buffer[0] == 'S' && buffer[1] == 'E' && buffer[2] == 'C') {
        printf("[!] SECRET KEY LEAKED via uninitialized memory!\n");
    }

    /* Check for pointer-sized values (address leak) */
    uint64_t *as_ptrs = (uint64_t *)buffer;
    for (int i = 0; i < 8; i++) {
        if (as_ptrs[i] > 0x7f0000000000ULL && as_ptrs[i] < 0x800000000000ULL) {
            printf("[!] Stack address leaked: 0x%lx (ASLR bypass)\n",
                   (unsigned long)as_ptrs[i]);
        }
    }
}

int main(void) {
    printf("=== Uninitialized Memory Read ===\n\n");
    printf("[*] Step 1: load_secret() writes sensitive data to the stack.\n");
    printf("[*] Step 2: load_secret() returns — data stays on the stack.\n");
    printf("[*] Step 3: read_uninitialized() reads the SAME stack memory.\n\n");

    load_secret();
    read_uninitialized();

    printf("\n[*] The fix: always initialize buffers (memset, = {0}, calloc).\n");
    printf("[*] This is how Heartbleed worked — reading uninitialized heap memory\n");
    printf("    leaked private keys, session tokens, and user credentials.\n");

    return 0;
}

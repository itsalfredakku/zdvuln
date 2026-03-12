/*
 * Signedness Bug
 *
 * Bug: a signed integer passes a bounds check (negative values are "less than
 * max"), then is used as an unsigned size in memcpy — becoming a massive
 * positive value that overflows the destination buffer.
 *
 * This is different from integer_overflow.c:
 *   - integer_overflow wraps via multiplication (arithmetic overflow)
 *   - signedness_bug passes a check via sign confusion (logic flaw)
 *
 * Real-world examples:
 *   - CVE-2018-14634: Linux kernel integer signedness in create_elf_tables
 *   - Many libc/kernel size_t vs ssize_t confusion bugs
 *   - Common in network code: length fields parsed as signed
 *
 * Study:
 *   - Why does a negative signed int pass a "< MAX" check?
 *   - How does (int)-1 become (size_t)0xFFFFFFFFFFFFFFFF?
 *   - Why is memcpy(dst, src, (size_t)negative_int) catastrophic?
 *
 * Build: zig build
 * Run:   ./zig-out/bin/signedness-bug
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_COPY_SIZE 256
#define DEST_SIZE     128

void process_data(const char *src, int length) {
    char dest[DEST_SIZE];

    printf("[*] Requested length: %d (signed)\n", length);
    printf("[*] As unsigned:      %u\n", (unsigned int)length);

    /*
     * BUG: bounds check uses SIGNED comparison.
     * If length is negative (e.g., -1), this check passes:
     *   -1 < 256  →  true (signed comparison)
     *
     * But memcpy interprets length as size_t (unsigned):
     *   (size_t)(-1) = 0xFFFFFFFFFFFFFFFF  →  massive copy
     */
    if (length < MAX_COPY_SIZE) {
        printf("[*] Bounds check passed (length %d < %d)\n", length, MAX_COPY_SIZE);

        /* VULNERABLE: negative length becomes huge unsigned value */
        memcpy(dest, src, (size_t)length);
        printf("[*] memcpy completed\n");
    } else {
        printf("[-] Bounds check REJECTED (length %d >= %d)\n", length, MAX_COPY_SIZE);
    }
}

int main(void) {
    printf("=== Signedness Bug ===\n\n");

    char source[512];
    memset(source, 'A', sizeof(source));

    /* Normal case — works fine */
    printf("--- Test 1: Normal length (64) ---\n");
    process_data(source, 64);
    printf("\n");

    /* Edge case — passes signed check, wraps to huge unsigned */
    printf("--- Test 2: Negative length (-1) ---\n");
    printf("[*] As signed int:  -1\n");
    printf("[*] As size_t:      %zu (0x%zx)\n", (size_t)(int)-1, (size_t)(int)-1);
    printf("[!] This passes the check (-1 < 256) but copies ~18 exabytes!\n\n");

    /* Let user try */
    printf("[?] Enter a length value (try negative numbers): ");
    fflush(stdout);

    int user_length;
    if (scanf("%d", &user_length) == 1) {
        printf("\n");
        process_data(source, user_length);
    }

    return 0;
}

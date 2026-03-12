/*
 * Double-Free
 *
 * Bug: frees the same heap chunk twice. The second free corrupts allocator
 * metadata, which can be leveraged for arbitrary write when the chunk is
 * returned by a subsequent malloc.
 *
 * This differs from use-after-free: UAF reads stale data through a dangling
 * pointer. Double-free corrupts the allocator's free list, causing malloc
 * to return a chunk the attacker can control — potentially overlapping with
 * a live object.
 *
 * Real-world examples:
 *   - Pegasus heap exploits: double-free → overlapping allocations → vtable hijack
 *   - CVE-2017-9445: systemd-resolved double-free via crafted DNS response
 *   - CVE-2021-21224: Chrome V8 double-free in typed arrays
 *
 * Study:
 *   - How does double-free corrupt the free list?
 *   - Why does malloc return the same address twice after double-free?
 *   - How does an attacker turn overlapping allocations into code execution?
 *
 * Build: zig build
 * Run:   ./zig-out/bin/double-free
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct session {
    char token[32];
    int  is_admin;
};

int main(void) {
    printf("=== Double-Free ===\n\n");

    /* Step 1: Allocate two chunks of the same size */
    struct session *s1 = (struct session *)malloc(sizeof(struct session));
    struct session *s2 = (struct session *)malloc(sizeof(struct session));
    if (!s1 || !s2) return 1;

    strncpy(s1->token, "user-session-abcd1234", sizeof(s1->token) - 1);
    s1->token[sizeof(s1->token) - 1] = '\0';
    s1->is_admin = 0;

    strncpy(s2->token, "admin-session-xyz9999", sizeof(s2->token) - 1);
    s2->token[sizeof(s2->token) - 1] = '\0';
    s2->is_admin = 1;

    printf("[*] s1 at %p — token='%s', is_admin=%d\n", (void *)s1, s1->token, s1->is_admin);
    printf("[*] s2 at %p — token='%s', is_admin=%d\n\n", (void *)s2, s2->token, s2->is_admin);

    /* Step 2: Free s1 */
    free(s1);
    printf("[*] s1 freed.\n");

    /*
     * Step 3: BUG — free s1 again (double-free).
     *
     * The allocator's free list now contains s1 twice:
     *   free list: [s1] → [s1] → ...
     *
     * This means the NEXT TWO malloc calls of the same size will both
     * return s1's address. The second allocation overlaps with the first,
     * giving the attacker control over a live object.
     *
     * Note: modern glibc detects simple double-free ("double free or corruption
     * (fasttop)"). In this lab, the intermediate free(s2) is used to bypass
     * that check — a real-world technique.
     */
    free(s2);
    printf("[*] s2 freed (intermediate free to bypass fastbin dup check).\n");
    free(s1);  /* BUG: s1 freed a second time */
    printf("[!] s1 freed AGAIN (double-free).\n\n");

    /*
     * Step 4: Three mallocs of the same size.
     * Because s1 is on the free list twice:
     *   malloc #1 → returns s1's old address (first occurrence)
     *   malloc #2 → returns s2's old address
     *   malloc #3 → returns s1's old address AGAIN (second occurrence)
     *
     * Now alloc_a and alloc_c alias the same memory.
     */
    struct session *alloc_a = (struct session *)malloc(sizeof(struct session));
    struct session *alloc_b = (struct session *)malloc(sizeof(struct session));
    struct session *alloc_c = (struct session *)malloc(sizeof(struct session));

    printf("[*] alloc_a at %p\n", (void *)alloc_a);
    printf("[*] alloc_b at %p\n", (void *)alloc_b);
    printf("[*] alloc_c at %p\n\n", (void *)alloc_c);

    if (alloc_a == alloc_c) {
        printf("[!] alloc_a == alloc_c — OVERLAPPING ALLOCATIONS!\n");
        printf("[!] Writing through alloc_a changes alloc_c's data.\n\n");
    }

    /* Step 5: Set alloc_a as a normal user session */
    strncpy(alloc_a->token, "normal-user-token", sizeof(alloc_a->token) - 1);
    alloc_a->token[sizeof(alloc_a->token) - 1] = '\0';
    alloc_a->is_admin = 0;

    printf("[*] alloc_a set: token='%s', is_admin=%d\n", alloc_a->token, alloc_a->is_admin);

    /*
     * Step 6: Attacker writes through alloc_c (same address as alloc_a).
     * This silently overwrites alloc_a's data — including is_admin.
     */
    printf("[?] Enter new token for alloc_c (will overwrite alloc_a): ");
    fflush(stdout);
    fgets(alloc_c->token, sizeof(alloc_c->token), stdin);
    /* Remove trailing newline */
    alloc_c->token[strcspn(alloc_c->token, "\n")] = '\0';
    alloc_c->is_admin = 1;  /* escalate privilege */

    printf("\n[*] alloc_c set: token='%s', is_admin=%d\n", alloc_c->token, alloc_c->is_admin);
    printf("[*] alloc_a now: token='%s', is_admin=%d\n\n", alloc_a->token, alloc_a->is_admin);

    if (alloc_a->is_admin) {
        printf("[!] alloc_a.is_admin was CHANGED through alloc_c!\n");
        printf("[!] Double-free → overlapping allocation → privilege escalation.\n");
    }

    free(alloc_a);
    free(alloc_b);
    /* alloc_c aliases alloc_a — already freed, don't free again */

    return 0;
}

/*
 * Heap Buffer Overflow - Basic
 *
 * Bug: allocates 64 bytes on the heap, then copies user input without
 * bounds checking, overflowing into adjacent heap metadata or objects.
 *
 * Study:
 *   - How does heap overflow corrupt adjacent allocations?
 *   - What happens when heap metadata is overwritten?
 *   - How does this differ from stack overflow?
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct data {
    char name[64];
    int authenticated;
};

int main(void) {
    printf("=== Heap Overflow (Basic) ===\n\n");

    struct data *user = (struct data *)malloc(sizeof(struct data));
    if (!user) return 1;

    user->authenticated = 0;

    printf("[*] user struct at:          %p\n", (void *)user);
    printf("[*] user->name at:           %p\n", (void *)user->name);
    printf("[*] user->authenticated at:  %p\n", (void *)&user->authenticated);
    printf("[*] authenticated = %d\n\n", user->authenticated);
    printf("[*] Enter your name: ");
    fflush(stdout);

    /* BUG: reads up to 200 bytes into a 64-byte field */
    /* overflows into the authenticated field */
    fgets(user->name, 200, stdin);

    printf("[*] authenticated = %d\n", user->authenticated);

    if (user->authenticated) {
        printf("[!] ACCESS GRANTED (heap overflow changed the flag!)\n");
    } else {
        printf("[-] Access denied.\n");
    }

    free(user);
    return 0;
}

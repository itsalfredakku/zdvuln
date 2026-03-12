/*
 * Use-After-Free
 *
 * Bug: frees a struct, then allocates new data that occupies the same memory,
 * then uses the old pointer — reading attacker-controlled data.
 *
 * Study:
 *   - Why does malloc return the same address after free?
 *   - How can an attacker control what fills freed memory?
 *   - How does this lead to code execution in real programs?
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct user {
    char name[32];
    int privilege_level;
};

int main(void) {
    printf("=== Use-After-Free ===\n\n");

    struct user *admin = (struct user *)malloc(sizeof(struct user));
    if (!admin) return 1;

    strncpy(admin->name, "admin", sizeof(admin->name) - 1);
    admin->name[sizeof(admin->name) - 1] = '\0';
    admin->privilege_level = 9999;

    printf("[*] admin at:              %p\n", (void *)admin);
    printf("[*] admin->name:           %s\n", admin->name);
    printf("[*] admin->privilege_level: %d\n\n", admin->privilege_level);

    /* Free the admin struct */
    free(admin);
    printf("[*] admin freed.\n\n");

    /* Allocate new data — likely reuses the same address */
    printf("[*] Enter replacement data (will fill freed memory): ");
    fflush(stdout);

    char *replacement = (char *)malloc(sizeof(struct user));
    if (!replacement) return 1;
    fgets(replacement, sizeof(struct user), stdin);

    printf("[*] replacement at: %p\n\n", (void *)replacement);

    /* BUG: use the old (freed) pointer */
    printf("[*] Reading through OLD pointer after free:\n");
    printf("[*] admin->name:           %s\n", admin->name);
    printf("[*] admin->privilege_level: %d\n", admin->privilege_level);

    if (admin->privilege_level != 9999) {
        printf("[!] Privilege level was CHANGED via use-after-free!\n");
    }

    free(replacement);
    return 0;
}

/*
 * Format String Vulnerability
 *
 * Bug: passes user input directly as a format string to printf.
 * Attacker can read stack memory with %x or write with %n.
 *
 * Study:
 *   - How does printf walk the stack using format specifiers?
 *   - How can %x leak stack contents?
 *   - How can %n write to arbitrary addresses?
 *   - Why is this equivalent to an arbitrary read/write primitive?
 */

#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== Format String Vulnerability ===\n\n");

    char buffer[256];
    int secret_value = 0x41414141;

    printf("[*] secret_value is at: %p\n", (void *)&secret_value);
    printf("[*] secret_value = 0x%08x\n\n", secret_value);
    printf("[*] Enter a string (try %%x.%%x.%%x.%%x): ");
    fflush(stdout);

    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = '\0';

    printf("[*] Your input: ");

    /* BUG: user input used as format string */
    printf(buffer);

    printf("\n[*] secret_value = 0x%08x\n", secret_value);
    return 0;
}

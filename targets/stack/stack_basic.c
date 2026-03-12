/*
 * Stack Buffer Overflow - Basic
 *
 * Bug: copies user input into a fixed-size stack buffer without bounds checking.
 * The buffer is 64 bytes but we read up to 256 bytes from stdin.
 *
 * Study:
 *   - How does overflowing the buffer overwrite the return address?
 *   - What happens with/without stack canaries?
 *   - Compile: zig cc -fno-stack-protector -o stack-basic stack_basic.c
 */

#include <stdio.h>
#include <string.h>

void vulnerable_function(void) {
    char buffer[64];
    printf("[*] buffer is at: %p\n", (void *)buffer);
    printf("[*] Enter input: ");
    fflush(stdout);

    /* BUG: reads up to 256 bytes into a 64-byte buffer */
    fgets(buffer, 256, stdin);

    printf("[*] You entered: %s\n", buffer);
}

int main(void) {
    printf("=== Stack Overflow (Basic) ===\n");
    printf("[*] Compile with: zig cc -fno-stack-protector -o stack-basic stack_basic.c\n\n");
    vulnerable_function();
    printf("[*] Returned normally.\n");
    return 0;
}

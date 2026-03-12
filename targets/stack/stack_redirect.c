/*
 * Stack Buffer Overflow - Return Address Overwrite
 *
 * Bug: same as basic, but includes a "secret" function that is never called.
 * By overwriting the return address, execution can be redirected to secret().
 *
 * Study:
 *   - Calculate the offset from buffer to saved return address
 *   - Craft input that redirects execution to secret()
 *   - Observe with: gdb ./stack-redirect, then `disassemble secret`
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void secret(void) {
    printf("\n[!] SECRET FUNCTION REACHED - you redirected execution!\n");
    exit(0);
}

void vulnerable_function(void) {
    char buffer[64];
    printf("[*] buffer is at:  %p\n", (void *)buffer);
    printf("[*] secret() is at: %p\n", (void *)secret);
    printf("[*] Enter input: ");
    fflush(stdout);

    /* BUG: reads far more than buffer can hold */
    fgets(buffer, 1024, stdin);
}

int main(void) {
    printf("=== Stack Overflow (Return Address Redirect) ===\n\n");
    vulnerable_function();
    printf("[*] Returned normally (secret not reached).\n");
    return 0;
}

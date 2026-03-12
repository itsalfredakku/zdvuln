/*
 * Off-by-One Stack Overflow
 *
 * Bug: writes exactly ONE byte past the end of a stack buffer. This single
 * byte overwrites the least significant byte of the saved frame pointer (RBP),
 * which shifts the caller's stack frame to an attacker-controlled location.
 * On the NEXT function return, the program loads a return address from the
 * shifted frame — giving the attacker RIP control.
 *
 * This is fundamentally different from stack_basic / stack_redirect:
 *   - Those overflow MANY bytes and directly overwrite the return address.
 *   - This overwrites ONE byte (the saved RBP LSB), and control flow
 *     hijack happens one function return LATER.
 *
 * Real-world examples:
 *   - OpenSSH 3.x off-by-one in channel handling
 *   - glibc off-by-one errors in string functions
 *   - Common in manual loop bounds: for(i=0; i<=len; i++) vs i<len
 *
 * Study:
 *   - Why does overwriting 1 byte of RBP eventually control RIP?
 *   - How does the "frame pointer chain" propagate the corruption?
 *   - Why is this harder to detect than a large overflow?
 *
 * Build: zig build
 * Run:   ./zig-out/bin/off-by-one
 */

#include <stdio.h>
#include <string.h>

#define BUFSIZE 64

void read_input(void) {
    char buffer[BUFSIZE];
    int i;

    printf("[*] buffer at:     %p\n", (void *)buffer);
    printf("[*] saved RBP at:  %p (approx)\n\n", (void *)(buffer + BUFSIZE));

    printf("[?] Enter input: ");
    fflush(stdout);

    /*
     * BUG: reads BUFSIZE bytes, but then null-terminates at position
     * buffer[len] where len can be BUFSIZE — writing one byte past
     * the buffer into the saved frame pointer.
     *
     * The classic off-by-one pattern:
     *   for (i = 0; i <= BUFSIZE; i++)   ← should be i < BUFSIZE
     * Or:
     *   buffer[strlen(input)] = '\0';    ← if input is exactly BUFSIZE
     */
    for (i = 0; i <= BUFSIZE; i++) {  /* BUG: <= instead of < */
        int c = getchar();
        if (c == '\n' || c == EOF) {
            buffer[i] = '\0';
            break;
        }
        buffer[i] = (char)c;
    }

    /* If loop completed without break, we wrote buffer[BUFSIZE] = last char.
     * That single byte overwrites the LSB of the saved RBP on the stack.
     *
     * Stack layout:
     *   [buffer: 64 bytes] [saved RBP: 8 bytes] [return addr: 8 bytes]
     *                       ^
     *                       buffer[64] overwrites the lowest byte here
     */

    printf("[*] Read %d bytes: %s\n", i, buffer);
    printf("[*] If input was exactly %d bytes, the saved RBP LSB is overwritten.\n", BUFSIZE);
    printf("[*] The corruption won't crash HERE — it crashes on the CALLER's return.\n");
}

int main(void) {
    printf("=== Off-by-One Stack Overflow ===\n\n");
    printf("[*] Unlike stack-basic, this writes only ONE byte past the buffer.\n");
    printf("[*] That single byte corrupts the saved frame pointer (RBP).\n");
    printf("[*] Control flow hijack happens on the NEXT function return.\n\n");

    read_input();

    printf("\n[*] Back in main — if RBP was corrupted, main's frame is shifted.\n");
    printf("[*] When main returns, it loads the return address from the wrong location.\n");
    return 0;
}

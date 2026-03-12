/*
 * Integer Overflow
 *
 * Bug: user-controlled size is multiplied, wrapping around to a small value.
 * A small buffer is allocated, then a large amount of data is copied into it.
 *
 * Study:
 *   - How does unsigned integer overflow work on 32-bit values?
 *   - Why does the allocation succeed with a tiny size?
 *   - How does Zig's @intCast detect this at runtime?
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    printf("=== Integer Overflow ===\n\n");

    uint32_t num_elements;
    printf("[*] Enter number of elements: ");
    fflush(stdout);

    if (scanf("%u", &num_elements) != 1) return 1;

    /* BUG: multiplication can wrap around */
    /* e.g., num_elements = 0x40000001, element_size = 8 */
    /* 0x40000001 * 8 = 0x200000008 → truncated to 0x00000008 on 32-bit */
    uint32_t element_size = 8;
    uint32_t total_size = num_elements * element_size;

    printf("[*] num_elements:  %u\n", num_elements);
    printf("[*] element_size:  %u\n", element_size);
    printf("[*] total_size:    %u (0x%08x)\n\n", total_size, total_size);

    if (total_size < num_elements) {
        printf("[!] Integer overflow detected! total_size wrapped around.\n");
        printf("[!] Would allocate only %u bytes for %u elements.\n", total_size, num_elements);
    }

    char *buffer = (char *)malloc(total_size);
    if (!buffer) {
        printf("[-] malloc failed\n");
        return 1;
    }

    printf("[*] Allocated %u bytes at %p\n", total_size, (void *)buffer);
    printf("[*] If this were real code, we'd now write %u * %u = overflow bytes into %u bytes.\n",
           num_elements, element_size, total_size);

    free(buffer);
    return 0;
}

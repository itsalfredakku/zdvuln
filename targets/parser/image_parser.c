/*
 * Minimal Image Format Parser
 *
 * Bug: trusts a width/height field from the file header without validating
 * that the declared dimensions match the actual data size. A crafted file
 * with inflated dimensions causes a heap buffer over-read/over-write during
 * pixel processing.
 *
 * This mirrors the class of bugs exploited in real-world attacks:
 *   - FORCEDENTRY (CVE-2021-30860): JBIG2 segment length overflow in iMessage
 *   - Pegasus GIF/image parser entry vectors
 *   - libpng, libjpeg, libwebp length-field bugs
 *
 * Minimal image format (ZDF - "zero-day format"):
 *   [MAGIC:4 "ZDF\x00"][WIDTH:4 LE][HEIGHT:4 LE][BPP:1][PIXEL DATA...]
 *
 * Study:
 *   - Why must a parser cross-check dimensions against actual file size?
 *   - How does an attacker craft a file to trigger a specific overflow size?
 *   - How does this differ from the protocol parser (network vs file input)?
 *
 * Build: zig build
 * Run:   ./zig-out/bin/image-parser <file.zdf>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ZDF_MAGIC "ZDF"
#define HEADER_SIZE 13  /* 4 magic + 4 width + 4 height + 1 bpp */
#define MAX_FILE_SIZE (1024 * 1024)  /* 1 MB cap for safety */

struct zdf_header {
    char     magic[4];
    uint32_t width;
    uint32_t height;
    uint8_t  bpp;       /* bytes per pixel: 1, 3, or 4 */
} __attribute__((packed));

void process_pixels(const uint8_t *pixels, uint32_t width, uint32_t height, uint8_t bpp) {
    /*
     * BUG: allocates a buffer based on the DECLARED dimensions from the header,
     * then copies pixel data into it. If the declared dimensions are larger than
     * the actual pixel data, this reads past the input buffer (over-read).
     * If we process and write back, it can also over-write.
     *
     * A real image decoder would do per-row or per-scanline decoding, but the
     * core bug is the same: trusting header dimensions without cross-checking
     * against actual data availability.
     */
    uint32_t expected_size = width * height * bpp;
    uint8_t *decoded = (uint8_t *)malloc(expected_size);
    if (!decoded) {
        printf("[-] malloc failed for decoded buffer\n");
        return;
    }

    printf("[*] Decoding %u x %u x %u = %u bytes\n", width, height, bpp, expected_size);

    /* VULNERABLE: copies expected_size bytes from pixels, which may be smaller */
    memcpy(decoded, pixels, expected_size);

    /* Simple "processing" — invert pixel values */
    for (uint32_t i = 0; i < expected_size; i++) {
        decoded[i] = ~decoded[i];
    }

    printf("[+] Processed %u pixels successfully\n", width * height);

    /* Show first 16 bytes of decoded output */
    printf("[*] First bytes: ");
    uint32_t show = expected_size < 16 ? expected_size : 16;
    for (uint32_t i = 0; i < show; i++) {
        printf("%02x ", decoded[i]);
    }
    printf("\n");

    free(decoded);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file.zdf>\n", argv[0]);
        return 1;
    }

    printf("=== ZDF Image Parser ===\n\n");

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Read entire file */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < HEADER_SIZE) {
        printf("[-] File too small for header\n");
        fclose(f);
        return 1;
    }

    if (file_size > MAX_FILE_SIZE) {
        printf("[-] File exceeds maximum size\n");
        fclose(f);
        return 1;
    }

    uint8_t *file_data = (uint8_t *)malloc((size_t)file_size);
    if (!file_data) {
        fclose(f);
        return 1;
    }

    if (fread(file_data, 1, (size_t)file_size, f) != (size_t)file_size) {
        printf("[-] Failed to read file\n");
        free(file_data);
        fclose(f);
        return 1;
    }
    fclose(f);

    /* Parse header */
    struct zdf_header hdr;
    memcpy(&hdr, file_data, sizeof(hdr));

    if (memcmp(hdr.magic, ZDF_MAGIC, 3) != 0) {
        printf("[-] Invalid magic: expected ZDF\n");
        free(file_data);
        return 1;
    }

    printf("[*] Magic:  ZDF\n");
    printf("[*] Width:  %u\n", hdr.width);
    printf("[*] Height: %u\n", hdr.height);
    printf("[*] BPP:    %u\n", hdr.bpp);

    size_t actual_pixels = (size_t)file_size - HEADER_SIZE;
    size_t declared_pixels = (size_t)hdr.width * hdr.height * hdr.bpp;

    printf("[*] Declared pixel data: %zu bytes\n", declared_pixels);
    printf("[*] Actual pixel data:   %zu bytes\n\n", actual_pixels);

    /*
     * BUG: does NOT check that declared_pixels <= actual_pixels.
     * A crafted ZDF file with width=1000, height=1000, bpp=4 but only
     * 16 bytes of actual pixel data will cause a massive over-read in
     * process_pixels(), and the memcpy will read past the file buffer
     * into adjacent heap memory.
     */
    if (hdr.bpp != 1 && hdr.bpp != 3 && hdr.bpp != 4) {
        printf("[-] Invalid BPP (must be 1, 3, or 4)\n");
        free(file_data);
        return 1;
    }

    const uint8_t *pixel_start = file_data + HEADER_SIZE;
    process_pixels(pixel_start, hdr.width, hdr.height, hdr.bpp);

    free(file_data);
    return 0;
}

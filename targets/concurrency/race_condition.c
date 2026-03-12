/*
 * Race Condition (TOCTOU — Time-of-Check-to-Time-of-Use)
 *
 * Bug: checks a file's properties, then operates on it — with a window
 * between check and use where an attacker can swap the file. The check
 * validates a safe file, but the operation acts on a dangerous one.
 *
 * This is fundamentally different from every other target in the lab:
 *   - No memory corruption at all
 *   - The bug is in TIMING, not in buffer sizes or type handling
 *   - Exploitation requires a concurrent process (the attacker swaps the file)
 *   - This is how privilege escalation works in real systems
 *
 * Real-world examples:
 *   - CVE-2016-2779: util-linux runuser TOCTOU privilege escalation
 *   - Symlink attacks on /tmp (check regular file → attacker replaces with symlink)
 *   - TOCTOU in setuid programs (check permissions → swap file → execute)
 *
 * Study:
 *   - Why can't you "just check first"? What's wrong with check-then-act?
 *   - How does an attacker win the race? (tight loop, nice priority, inotify)
 *   - What's the fix? (O_NOFOLLOW, open-then-fstat, atomic operations)
 *
 * Build: zig build
 * Run:   ./zig-out/bin/race-condition
 *
 * To exploit: while this runs, in another terminal rapidly swap the file:
 *   while true; do ln -sf /etc/shadow /tmp/toctou_target 2>/dev/null; \
 *                  ln -sf /tmp/safe.txt /tmp/toctou_target 2>/dev/null; done
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define TARGET_FILE "/tmp/toctou_target"

/* Simulated "safe" check — verifies the file is a regular file owned by us */
int check_file_safe(const char *path) {
    struct stat st;

    if (lstat(path, &st) != 0) {
        perror("lstat");
        return 0;
    }

    /* Check: must be a regular file (not a symlink, not a device) */
    if (!S_ISREG(st.st_mode)) {
        printf("[-] REJECTED: not a regular file\n");
        return 0;
    }

    /* Check: must be owned by current user */
    if (st.st_uid != getuid()) {
        printf("[-] REJECTED: file not owned by us (owner=%d, us=%d)\n",
               st.st_uid, getuid());
        return 0;
    }

    printf("[+] PASSED: regular file, owned by uid %d\n", st.st_uid);
    return 1;
}

void use_file(const char *path) {
    /*
     * BUG: TOCTOU — gap between check_file_safe() and this fopen().
     *
     * Between the lstat() in check_file_safe() and the fopen() here,
     * an attacker can replace the file with a symlink to /etc/shadow
     * or any other sensitive file. The check validated the OLD file,
     * but fopen() follows the NEW symlink.
     *
     * Timeline:
     *   1. check_file_safe("/tmp/toctou_target")  →  lstat says "regular file, safe"
     *   2. *** ATTACKER: ln -sf /etc/shadow /tmp/toctou_target ***
     *   3. use_file("/tmp/toctou_target")  →  fopen follows symlink to /etc/shadow
     */

    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return;
    }

    printf("[*] Reading file contents:\n");
    char line[256];
    int lines = 0;
    while (fgets(line, sizeof(line), f) && lines < 5) {
        printf("    %s", line);
        lines++;
    }
    if (lines >= 5) printf("    ... (truncated)\n");

    fclose(f);
}

int main(void) {
    printf("=== Race Condition (TOCTOU) ===\n\n");
    printf("[*] This target checks if a file is safe, then reads it.\n");
    printf("[*] An attacker can swap the file BETWEEN the check and the read.\n\n");

    /* Create a safe file for the demo */
    FILE *f = fopen(TARGET_FILE, "w");
    if (!f) {
        printf("[-] Could not create %s\n", TARGET_FILE);
        printf("[-] Make sure /tmp is writable.\n");
        return 1;
    }
    fprintf(f, "This is safe, harmless content.\nNothing sensitive here.\n");
    fclose(f);

    printf("[*] Created safe file: %s\n", TARGET_FILE);
    printf("[*] To exploit: in another terminal, run:\n");
    printf("    while true; do ln -sf /etc/passwd %s 2>/dev/null; ", TARGET_FILE);
    printf("ln -sf /tmp/safe_backup.txt %s 2>/dev/null; done\n\n", TARGET_FILE);

    /* Simulate the vulnerable pattern in a loop */
    for (int attempt = 0; attempt < 5; attempt++) {
        printf("--- Attempt %d ---\n", attempt + 1);

        /* STEP 1: Check the file */
        if (check_file_safe(TARGET_FILE)) {
            /*
             * TOCTOU WINDOW: this sleep simulates the gap between check and use.
             * In real code, the gap may be microseconds — but it's still exploitable
             * with a fast-enough swap loop.
             */
            printf("[*] (sleeping 1s — TOCTOU window open)\n");
            sleep(1);

            /* STEP 2: Use the file — may now be a different file! */
            use_file(TARGET_FILE);
        }

        printf("\n");
    }

    /* Cleanup */
    unlink(TARGET_FILE);

    printf("[*] Fix: open() the file FIRST, then fstat() the fd — not the path.\n");
    printf("[*] The fd always refers to the same file, even if the path changes.\n");

    return 0;
}

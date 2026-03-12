/*
 * Type Confusion
 *
 * Bug: a tagged union where the type tag can be corrupted, causing the program
 * to interpret one type's data as another. Reading an integer field through
 * a string pointer (or vice versa) gives an information leak or controlled
 * memory access.
 *
 * This mirrors real-world type confusion bugs in:
 *   - JavaScript engines (V8, SpiderMonkey) — object type maps
 *   - Media codecs — variant containers with wrong type dispatch
 *   - Serialization frameworks — deserialized object type mismatch
 *
 * Study:
 *   - Why is type confusion dangerous even without a buffer overflow?
 *   - How does confusing a pointer type with an integer give a read primitive?
 *   - How does confusing an integer with a pointer give a write primitive?
 *
 * Build: zig build
 * Run:   ./zig-out/bin/type-confusion
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TYPE_STRING  1
#define TYPE_INTEGER 2
#define TYPE_BUFFER  3

struct variant {
    int type;
    union {
        char     *str_val;     /* TYPE_STRING:  pointer to heap string */
        int64_t   int_val;     /* TYPE_INTEGER: 64-bit integer value */
        struct {
            uint8_t *data;     /* TYPE_BUFFER:  pointer to raw data */
            size_t   length;
        } buf_val;
    };
};

/* Create a new string variant */
struct variant *create_string(const char *s) {
    struct variant *v = (struct variant *)malloc(sizeof(struct variant));
    if (!v) return NULL;
    v->type = TYPE_STRING;
    v->str_val = strdup(s);
    return v;
}

/* Create a new integer variant */
struct variant *create_integer(int64_t val) {
    struct variant *v = (struct variant *)malloc(sizeof(struct variant));
    if (!v) return NULL;
    v->type = TYPE_INTEGER;
    v->int_val = val;
    return v;
}

/* Create a new buffer variant */
struct variant *create_buffer(const uint8_t *data, size_t len) {
    struct variant *v = (struct variant *)malloc(sizeof(struct variant));
    if (!v) return NULL;
    v->type = TYPE_BUFFER;
    v->buf_val.data = (uint8_t *)malloc(len);
    if (!v->buf_val.data) { free(v); return NULL; }
    memcpy(v->buf_val.data, data, len);
    v->buf_val.length = len;
    return v;
}

/*
 * Print a variant's value based on its type tag.
 * This function trusts the type field — if corrupted, it interprets
 * the union data using the wrong type.
 */
void print_variant(const struct variant *v) {
    switch (v->type) {
        case TYPE_STRING:
            printf("[STRING]  \"%s\"\n", v->str_val);
            break;
        case TYPE_INTEGER:
            printf("[INTEGER] %ld (0x%lx)\n", v->int_val, (unsigned long)v->int_val);
            break;
        case TYPE_BUFFER:
            printf("[BUFFER]  %zu bytes at %p\n", v->buf_val.length, (void *)v->buf_val.data);
            break;
        default:
            printf("[UNKNOWN] type=%d\n", v->type);
    }
}

void free_variant(struct variant *v) {
    if (!v) return;
    if (v->type == TYPE_STRING) free(v->str_val);
    if (v->type == TYPE_BUFFER) free(v->buf_val.data);
    free(v);
}

int main(void) {
    printf("=== Type Confusion ===\n\n");

    /* Create a string variant — str_val is a heap pointer */
    struct variant *v1 = create_string("sensitive_data_here");
    printf("[*] v1 created as STRING:\n    ");
    print_variant(v1);
    printf("[*] v1 at %p, str_val pointer = %p\n\n", (void *)v1, (void *)v1->str_val);

    /* Create an integer variant */
    struct variant *v2 = create_integer(0xDEADBEEFCAFEBABE);
    printf("[*] v2 created as INTEGER:\n    ");
    print_variant(v2);
    printf("\n");

    /*
     * BUG: Simulate type tag corruption.
     * An attacker who can overwrite the type field (via adjacent overflow,
     * use-after-free, etc.) changes how the union is interpreted.
     *
     * Confusion 1: INTEGER treated as STRING
     * The int_val (0xDEADBEEFCAFEBABE) is interpreted as a char* pointer.
     * printf("%s", ...) will dereference this address → SIGSEGV or info leak.
     */
    printf("[!] Corrupting v2->type from INTEGER to STRING...\n");
    v2->type = TYPE_STRING;  /* BUG: type confusion */
    printf("[!] v2 now treated as STRING:\n    ");
    printf("[*] Will dereference 0x%lx as a string pointer\n",
           (unsigned long)v2->int_val);
    /* print_variant(v2);  ← would crash: dereferences 0xDEADBEEFCAFEBABE as char* */

    /* Restore for next demo */
    v2->type = TYPE_INTEGER;

    /*
     * Confusion 2: STRING treated as INTEGER
     * The str_val (a heap pointer) is interpreted as an integer.
     * This LEAKS the heap address — an information leak primitive.
     */
    printf("\n[!] Corrupting v1->type from STRING to INTEGER...\n");
    int saved_type = v1->type;
    v1->type = TYPE_INTEGER;  /* BUG: type confusion */
    printf("[!] v1 now treated as INTEGER:\n    ");
    print_variant(v1);
    printf("[!] The 'integer' above is actually the heap pointer to \"%s\"\n",
           (char *)(uintptr_t)v1->int_val);
    printf("[!] This is an ADDRESS LEAK — ASLR bypass primitive.\n\n");

    v1->type = saved_type;  /* restore for cleanup */

    /*
     * Confusion 3: User-controlled type tag
     * Let the user choose what type to interpret the data as.
     */
    struct variant *v3 = create_integer(0x4141414141414141);
    printf("[*] v3 created as INTEGER with value 0x4141414141414141\n");
    printf("[?] Enter type to interpret v3 as (1=STRING, 2=INTEGER, 3=BUFFER): ");
    fflush(stdout);

    int user_type;
    if (scanf("%d", &user_type) == 1) {
        v3->type = user_type;  /* BUG: attacker controls the type tag */
        printf("[!] Interpreting v3 as type %d:\n    ", user_type);
        if (user_type == TYPE_STRING) {
            printf("[*] Would dereference 0x4141414141414141 as char* → crash\n");
        } else {
            print_variant(v3);
        }
    }

    printf("\n[*] Type confusion gives two primitives:\n");
    printf("    - Pointer → Integer = ADDRESS LEAK (bypass ASLR)\n");
    printf("    - Integer → Pointer = ARBITRARY READ/WRITE (if attacker controls the value)\n");

    /* Cleanup — restore correct types */
    v3->type = TYPE_INTEGER;
    free_variant(v1);
    free_variant(v2);
    free_variant(v3);

    return 0;
}

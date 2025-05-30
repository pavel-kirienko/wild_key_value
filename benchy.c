/// Benchmark for the Wild Key-Value (WKV) library.
/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WKV_NO_ASSERT   1
#define WKV_KEY_MAX_LEN 100
#include "wkv.h"

#define GIGA 1000000000ULL

#define SEGMENTS 3U
#define SEG_LEN  5U
static const char ALPHABET[] = "abcd";

static void* std_realloc(struct wkv_t* const self, void* const ptr, const size_t new_size)
{
    (void)self;
    if (new_size > 0) {
        return realloc(ptr, new_size);
    }
    free(ptr);
    return NULL;
}

static char* make_random_key(const size_t idx)
{
    char* const key = malloc(WKV_KEY_MAX_LEN + 1U);
    if (!key) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    char* p = key;
    for (unsigned seg = 0; seg < SEGMENTS; ++seg) {
        for (unsigned c = 0; c < SEG_LEN; ++c) {
            *p++ = ALPHABET[rand() % (sizeof ALPHABET - 1U)];
        }
        *p++ = '/';
    }
    sprintf(p, "%zu", idx); // Append the index to ensure uniqueness
    return key;
}

// Fisher-Yates shuffle of an array of indices (for random access order)
static void shuffle_indices(size_t* const idx, const size_t n)
{
    for (size_t i = n - 1U; i > 0U; --i) {
        const size_t j = (size_t)rand() % (i + 1U);
        const size_t t = idx[i];
        idx[i]         = idx[j];
        idx[j]         = t;
    }
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * GIGA + (uint64_t)ts.tv_nsec;
}

int main(int argc, char* argv[])
{
    srand((unsigned)time(NULL));

    const long key_count = (argc > 1) ? strtol(argv[1], NULL, 10) : 1000L;

    // ------------------------------------------------------------------
    // 1. Prepare dataset and container
    // ------------------------------------------------------------------
    char* keys[key_count];
    for (size_t i = 0; i < key_count; ++i) {
        keys[i] = make_random_key(i);
    }

    struct wkv_t kv = wkv_init(std_realloc);

    size_t order[key_count];
    for (size_t i = 0; i < key_count; ++i) {
        order[i] = i;
    }

    // ------------------------------------------------------------------
    // 2. Benchmark create (first insertion)
    // ------------------------------------------------------------------
    shuffle_indices(order, key_count);
    uint64_t t0 = now_ns();
    for (size_t i = 0; i < key_count; ++i) {
        const size_t k = order[i];
        void* const  v = (void*)(uintptr_t)(k + key_count * 1); // dummy unique value
        if (wkv_set(&kv, keys[k], v) == NULL) {
            fprintf(stderr, "Create failed at %zu\n", k);
            return EXIT_FAILURE;
        }
    }
    const uint64_t t_create = now_ns() - t0;

    // ------------------------------------------------------------------
    // 3. Benchmark modify (overwrite existing value)
    // ------------------------------------------------------------------
    shuffle_indices(order, key_count);
    t0 = now_ns();
    for (size_t i = 0; i < key_count; ++i) {
        const size_t k = order[i];
        void*        v = (void*)(uintptr_t)(k + key_count * 2); // new dummy value
        if (wkv_set(&kv, keys[k], v) == NULL) {
            fprintf(stderr, "Modify failed at %zu\n", k);
            return EXIT_FAILURE;
        }
    }
    const uint64_t t_modify = now_ns() - t0;

    // ------------------------------------------------------------------
    // 4. Benchmark read (lookup)
    // ------------------------------------------------------------------
    shuffle_indices(order, key_count);
    volatile uintptr_t sink = 0; // prevent the compiler from eliding the lookup
    t0                      = now_ns();
    for (size_t i = 0; i < key_count; ++i) {
        const size_t k = order[i];
        sink ^= (uintptr_t)wkv_get(&kv, keys[k]);
    }
    const uint64_t t_read = now_ns() - t0;
    (void)sink;

    // ------------------------------------------------------------------
    // 5. Benchmark delete (erase)
    // ------------------------------------------------------------------
    shuffle_indices(order, key_count);
    t0 = now_ns();
    for (size_t i = 0; i < key_count; ++i) {
        const size_t k = order[i];
        if (wkv_set(&kv, keys[k], NULL) == NULL) {
            fprintf(stderr, "Delete failed at %zu\n", k);
            return EXIT_FAILURE;
        }
    }
    const uint64_t t_delete = now_ns() - t0;

    // ------------------------------------------------------------------
    // 6. Report results
    // ------------------------------------------------------------------
    printf("== Wild Key-Value micro-benchmark (%lu keys) ==\n\n", key_count);
    printf("Operation   Total (µs)   Average (ns/op)\n");
    printf("-----------------------------------------\n");
    printf("Create   : %10.3f   %14.1f\n", (double)t_create * 1e-3, (double)t_create / key_count);
    printf("Modify   : %10.3f   %14.1f\n", (double)t_modify * 1e-3, (double)t_modify / key_count);
    printf("Read     : %10.3f   %14.1f\n", (double)t_read * 1e-3, (double)t_read / key_count);
    printf("Delete   : %10.3f   %14.1f\n", (double)t_delete * 1e-3, (double)t_delete / key_count);

    // ------------------------------------------------------------------
    // 7. Clean-up
    // ------------------------------------------------------------------
    while (!wkv_is_empty(&kv)) {
        char        buf[WKV_KEY_MAX_LEN + 1];
        void* const v = wkv_at(&kv, 0, buf, NULL);
        if (v == NULL) {
            fprintf(stderr, "Failed to retrieve key for deletion\n");
            return EXIT_FAILURE;
        }
        if (wkv_set(&kv, buf, NULL) == NULL) {
            fprintf(stderr, "Failed to delete key '%s'\n", buf);
            return EXIT_FAILURE;
        }
    }
    for (size_t i = 0; i < key_count; ++i) {
        free(keys[i]);
    }
    return 0;
}

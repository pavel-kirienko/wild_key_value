/// Benchmark for the Wild Key-Value (WKV) library.
/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>

#define WKV_NO_ASSERT 1
#include "wkv.h"

#define ITERS 100000U
static const char ALPHABET[] = "abc";

static void* std_realloc(wkv_t* const self, void* const ptr, const size_t new_size)
{
    (void)self;
    if (new_size > 0) {
        return realloc(ptr, new_size);
    }
    free(ptr);
    return NULL;
}

static wkv_str_t make_random_key(const size_t idx, const size_t n_segments)
{
    char* const key = malloc(100);
    if (!key) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    size_t segment_len_max = n_segments + 1;
    char*  p               = key;
    for (unsigned seg = 0; seg < n_segments; ++seg) {
        const size_t segment_len = (rand() % segment_len_max) + 1;
        for (unsigned c = 0; c < segment_len; ++c) {
            *p++ = ALPHABET[rand() % (sizeof ALPHABET - 1U)];
        }
        segment_len_max = (segment_len_max > 1) ? (segment_len_max - 1) : 1;
        *p++            = '/';
    }
    sprintf(p, "%zu", idx); // Append the index to ensure uniqueness
    return wkv_key(key);
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + (1e-9 * ts.tv_nsec);
}

static void print_tree(const wkv_node_t* const node, const size_t depth)
{
    const int indent = (int)(depth * 2);
    for (size_t i = 0; i < node->n_edges; ++i) {
        const wkv_edge_t* const edge = node->edges[i];
        char                    value[256];
        if (edge->node.value != NULL) {
            (void)snprintf(value, sizeof(value), "%p", edge->node.value);
        } else {
            value[0] = '\0';
        }
        printf("%*s#%zu '%s': %s\n", indent, "", i, edge->seg, value);
        print_tree(&edge->node, depth + 1);
    }
}

int main(int argc, char* argv[])
{
    srand((unsigned)time(NULL));

    const long key_count = (argc > 1) ? strtol(argv[1], NULL, 10) : 100L;

    // ------------------------------------------------------------------
    // 1. Prepare dataset and container
    // ------------------------------------------------------------------
    fprintf(stderr, "Preparing the test with %lu keys...\n", key_count);
    wkv_str_t keys[key_count];
    for (size_t i = 0; i < key_count; ++i) {
        keys[i] = make_random_key(i, (size_t)round(log10(key_count)));
    }
    wkv_t kv;
    wkv_init(&kv, std_realloc);

    // ------------------------------------------------------------------
    // 2. Benchmark create (first insertion)
    // ------------------------------------------------------------------
    fprintf(stderr, "Creating items...\n");
    double t0 = now();
    for (size_t i = 0; i < key_count; ++i) {
        wkv_set(&kv, keys[i])->value = (void*)(uintptr_t)(i + key_count * 1); // dummy unique value
    }
    const double t_create = now() - t0;

    // ------------------------------------------------------------------
    // 3. Benchmark modify (overwrite existing value)
    // ------------------------------------------------------------------
    fprintf(stderr, "Modifying items...\n");
    t0 = now();
    for (size_t z = 0; z < ITERS; ++z) {
        for (size_t i = 0; i < key_count; ++i) {
            wkv_set(&kv, keys[i])->value = (void*)(uintptr_t)(i + key_count * 2); // new dummy value
        }
    }
    const double t_modify = now() - t0;

    // ------------------------------------------------------------------
    // 4. Benchmark read (lookup)
    // ------------------------------------------------------------------
    fprintf(stderr, "Reading items...\n");
    volatile uintptr_t sink = 0; // prevent the compiler from eliding the lookup
    t0                      = now();
    for (size_t z = 0; z < ITERS; ++z) {
        for (size_t i = 0; i < key_count; ++i) {
            sink ^= (uintptr_t)wkv_get(&kv, keys[i]);
        }
    }
    const double t_read = now() - t0;
    (void)sink;

    // Visualize the tree before deletion.
    print_tree(&kv.root, 0);

    // ------------------------------------------------------------------
    // 5. Benchmark delete (erase), existing and non-existing keys
    // ------------------------------------------------------------------
    fprintf(stderr, "Deleting items...\n");
    t0 = now();
    for (size_t i = 0; i < key_count; ++i) {
        wkv_del(&kv, wkv_get(&kv, keys[i]));
    }
    const double t_del_existing = now() - t0;

    t0 = now();
    for (size_t z = 0; z < ITERS; ++z) {
        for (size_t i = 0; i < key_count; ++i) {
            wkv_del(&kv, wkv_get(&kv, keys[i]));
        }
    }
    const double t_del_nonexist = now() - t0;

    // ------------------------------------------------------------------
    // 6. Report results
    // ------------------------------------------------------------------
    printf("== Wild Key-Value micro-benchmark (%lu keys) ==\n\n", key_count);
    printf("Operation   Total (s)   Average (ns/op)\n");
    printf("-----------------------------------------\n");
    printf("Create   : %6.3f   %14.1f\n", t_create, 1e9 * t_create / key_count);
    printf("Modify   : %6.3f   %14.1f\n", t_modify, 1e9 * t_modify / (ITERS * key_count));
    printf("Read     : %6.3f   %14.1f\n", t_read, 1e9 * t_read / (ITERS * key_count));
    printf("Del. ex  : %6.3f   %14.1f\n", t_del_existing, 1e9 * t_del_existing / key_count);
    printf("Del. nex : %6.3f   %14.1f\n", t_del_nonexist, 1e9 * t_del_nonexist / (ITERS * key_count));

    // ------------------------------------------------------------------
    // 7. Clean-up
    // ------------------------------------------------------------------
    while (!wkv_is_empty(&kv)) {
        wkv_del(&kv, wkv_at(&kv, 0));
    }
    for (size_t i = 0; i < key_count; ++i) {
        free((void*)keys[i].str);
    }
    return 0;
}

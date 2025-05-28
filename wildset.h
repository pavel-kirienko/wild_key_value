/// Source: https://github.com/pavel-kirienko/wildset
///
/// See also:
///
/// - O1Heap <https://github.com/pavel-kirienko/o1heap> -- a deterministic memory manager for hard-real-time
///   high-integrity embedded systems.
///
/// -------------------------------------------------------------------------------------------------------------------
///
/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
/// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
/// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
/// and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all copies or substantial portions of
/// the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
/// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
/// OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
/// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// ReSharper disable CppCStyleCast CppZeroConstantCanBeReplacedWithNullptr
// ReSharper disable CppRedundantElaboratedTypeSpecifier CppRedundantInlineSpecifier
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/// If Wildset is used in throughput-critical code, then it is recommended to disable assertion checks as they may
/// be costly in terms of execution time.
#ifndef WILDSET_ASSERT
#if defined(WILDSET_NO_ASSERT) && WILDSET_NO_ASSERT
#define WILDSET_ASSERT(x) (void)0
#else
#include <assert.h>
#define WILDSET_ASSERT(x) assert(x)
#endif
#endif

#ifdef __cplusplus
// This is, strictly speaking, useless because we do not define any functions with external linkage here,
// but it tells static analyzers that what follows should be interpreted as C code rather than C++.
extern "C"
{
#endif

// ----------------------------------------         PUBLIC API SECTION         ----------------------------------------

/// This is used for safe string operations and to allocate temporary storage on the stack during insertion.
#ifndef WILDSET_KEY_MAX_LEN
#error "WILDSET_KEY_MAX_LEN must be defined as a positive integer value"
#endif

struct wildset_node_t
{
    size_t                  n_edges;
    struct wildset_edge_t** edges;   ///< Contiguous edge pointers ordered lexicographically for bisection.
    void*                   payload; ///< NULL if this is not a full key.
};

struct wildset_edge_t
{
    struct wildset_node_t next; ///< Base type.

    /// This is a flex array; it may be shorter than this depending on the segment length.
    /// https://www.open-std.org/Jtc1/sc22/wg14/www/docs/dr_051.html
    char seg[WILDSET_KEY_MAX_LEN + 1];
};

/// When a new entry is inserted, Wildset needs to allocate tree nodes in the dynamic memory.
/// There are allocations of the following sizes:
/// - sizeof(struct wildset_node_t) + strlen(key_segment) + 1
/// - n_edges * sizeof(pointer)
///
/// Realloc is used to allocate new memory with the original pointer being NULL, and also to resize the edges pointer
/// array when entries are added/removed.
/// The semantics are per the standard realloc from stdlib, with one difference: if the fragment is reduced in size,
/// reallocation must always succeed.
///
/// The recommended allocator is O1Heap: https://github.com/pavel-kirienko/o1heap
typedef void* (*wildset_realloc_t)(struct wildset_t* self, void* ptr, size_t new_size);
typedef void (*wildset_free_t)(struct wildset_t* self, void* ptr);

/// Invoked on every match while searching.
typedef void (*wildset_on_match_t)(struct wildset_t* self, void* context, void* payload);

struct wildset_t
{
    struct wildset_node_t root; ///< Base type.

    wildset_realloc_t realloc;
    wildset_free_t    free;

    void* context; ///< Can be assigned by the user code arbitrarily.
};

/// Use this to create a new Wildset instance. The context pointer can be set and mutated arbitrarily later.
static inline struct wildset_t wildset_init(const wildset_realloc_t realloc, const wildset_free_t free)
{
    return (struct wildset_t){ .root = { .edges = NULL }, .realloc = realloc, .free = free };
}

/// None of the pointers are allowed to be NULL.
/// Returns:
/// - Payload as-is on success.
/// - If this key is already known (not unique), the payload value of the existing key.
/// - NULL if out of memory.
/// Therefore, to check if the key is inserted successfully, compare the returned value against the original payload.
static inline void* wildset_add(struct wildset_t* const self, const char* const key, const char sep, void* const payload);

/// Returns true if the key was removed, false if it didn't exist.
static inline bool wildset_remove(struct wildset_t* const self, const char* const key, const char sep);

/// Find keys in the tree of keys that match the given wildcard pattern.
/// The pattern doesn't actually have to be a pattern, it can be an ordinary key name as well.
static inline void wildset_find_keys(struct wildset_t* const  self,
                                     const char* const        pat,
                                     const char               star,
                                     void* const              context,
                                     const wildset_on_match_t on_match);

/// Find wildcard patterns in the tree of patterns that match the given key.
static inline void wildset_find_pats(struct wildset_t* const  self,
                                     const char* const        key,
                                     const char               star,
                                     void* const              context,
                                     const wildset_on_match_t on_match);

// ----------------------------------------     END OF PUBLIC API SECTION      ----------------------------------------
// ----------------------------------------      POLICE LINE DO NOT CROSS      ----------------------------------------

static inline void _wildset_free(struct wildset_t* const self, void* const ptr)
{
    WILDSET_ASSERT(self != NULL);
    if (ptr != NULL) {
        self->free(self, ptr);
    }
}

/// Allocates the edge and its key segment in the same dynamically-sized memory block.
static struct wildset_edge_t* _wildset_edge_new(struct wildset_t* const self, const char* const str)
{
    WILDSET_ASSERT(str != NULL);
    const size_t                 len = strnlen(str, WILDSET_KEY_MAX_LEN);
    struct wildset_edge_t* const edge =
      (struct wildset_edge_t*)self->realloc(self, NULL, sizeof(struct wildset_node_t) + len + 1U);
    if (edge != NULL) {
        edge->next = (struct wildset_node_t){ .n_edges = 0, .edges = NULL, .payload = NULL };
        memcpy(&edge->seg[0], str, len);
        edge->seg[len] = '\0';
    }
    return edge;
}

/// Binary search inside n->edge (which we keep sorted). Returns insertion point if the segment is not found.
static ptrdiff_t _wildset_bisect(struct wildset_node_t* const node, const char* const seg)
{
    WILDSET_ASSERT((node != NULL) && (seg != NULL));
    size_t lo = 0;
    size_t hi = node->n_edges;
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2U;
        const int    cmp = strncmp(seg, node->edges[mid]->seg, WILDSET_KEY_MAX_LEN);
        if (cmp == 0) {
            return (ptrdiff_t)mid;
        }
        if (cmp < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return -(((ptrdiff_t)lo) + 1); // insertion point
}

static inline void* wildset_add(struct wildset_t* const self, const char* const key, const char sep, void* const payload)
{
    if ((self == NULL) || (key == NULL) || (sep == '\0') || (payload == NULL)) {
        WILDSET_ASSERT(false);
        return NULL;
    }
    struct wildset_node_t* n = &self->root;
    const char*            p = key;
    for (;;) {
        const char* const seg_end = (const char*)memchr(p, sep, WILDSET_KEY_MAX_LEN);
        const size_t      len     = (seg_end != NULL) ? (size_t)(seg_end - p) : strnlen(p, WILDSET_KEY_MAX_LEN);

        char segbuf[WILDSET_KEY_MAX_LEN + 1U];
        memcpy(segbuf, p, len);
        segbuf[len] = '\0';

        ptrdiff_t k = _wildset_bisect(n, segbuf);
        if (k < 0) { // Insort the new edge.
            k = -(k + 1);
            WILDSET_ASSERT((k >= 0) && (k <= (ptrdiff_t)n->n_edges));
            // Expand the edge pointer array and allocate the new edge. This may fail.
            struct wildset_edge_t* new_e = NULL;
            {
                struct wildset_edge_t** const new_edges = (struct wildset_edge_t**)self->realloc(
                  self, n->edges, (n->n_edges + 1) * sizeof(struct wildset_edge_t*));
                if (new_edges != NULL) {  // Even if we bail later, we keep this larger array allocated as-is.
                    n->edges = new_edges; // It will be resized on next removal or insertion.
                    new_e    = _wildset_edge_new(self, segbuf);
                }
            }
            WILDSET_ASSERT(n->edges != NULL);
            if (new_e == NULL) {
                // TODO: handle allocation failure -- backtrack to remove the edges that we created so far.
                // copy (key...p) into segbuf and invoke wildset_remove()?
            } else {
                memmove(&n->edges[k + 1], &n->edges[k], (n->n_edges - k) * sizeof(struct wildset_edge_t*));
                n->edges[k] = new_e;
                n->n_edges++;
            }
        }
        n = &n->edges[k]->next;
        if (!seg_end) {
            break; // last segment consumed
        }
        p = seg_end + 1;
    }
    n->payload = payload;
}

#ifdef __cplusplus
}
#endif

/// Source: https://github.com/pavel-kirienko/wild_key_value
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

/// If Wild Key-Value is used in throughput-critical code, then it is recommended to disable assertion checks
/// as they may be costly in terms of execution time.
#ifndef WKV_ASSERT
#if defined(WKV_NO_ASSERT) && WKV_NO_ASSERT
#define WKV_ASSERT(x) (void)0
#else
#include <assert.h>
#define WKV_ASSERT(x) assert(x)
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
#ifndef WKV_KEY_MAX_LEN
#error "WKV_KEY_MAX_LEN must be defined as a positive integer value"
#endif

struct wkv_node_t
{
    struct wkv_node_t*  parent; ///< NULL if this is the root node.
    size_t              n_edges;
    struct wkv_edge_t** edges;   ///< Contiguous edge pointers ordered lexicographically for bisection.
    void*               payload; ///< NULL if this is not a full key.
};

struct wkv_edge_t
{
    struct wkv_node_t node; ///< Base type.
    size_t            seg_len;
    /// This is a flex array; it may be shorter than this depending on the segment length.
    /// It is always null-terminated, so it can be used as a C string.
    /// https://www.open-std.org/Jtc1/sc22/wg14/www/docs/dr_051.html
    char seg[WKV_KEY_MAX_LEN + 1];
};

/// When a new entry is inserted, Wild Key-Value needs to allocate tree nodes in the dynamic memory.
/// There are allocations of the following sizes:
/// - sizeof(struct wkv_node_t) + strlen(key_segment) + 1
/// - n_edges * sizeof(pointer)
/// Each node takes one allocation, unless it has no outgoing edges; each edge takes one allocation always.
///
/// Realloc is used to allocate new memory with the original pointer being NULL, and also to resize the edges pointer
/// array when entries are added/removed.
/// The semantics are per the standard realloc from stdlib, with one difference: if the fragment is reduced in size,
/// reallocation must always succeed.
///
/// The recommended allocator is O1Heap: https://github.com/pavel-kirienko/o1heap
typedef void* (*wkv_realloc_t)(struct wkv_t* self, void* ptr, size_t new_size);
typedef void (*wkv_free_t)(struct wkv_t* self, void* ptr);

/// Invoked on every match while searching.
/// Searching stops when this function returns a non-NULL value, which is then propagated back to the caller.
typedef void* (*wkv_on_match_t)(struct wkv_t* self, void* context, void* payload);

/// Once initialized, the instance shall not be moved or copied, as that breaks parent links in the tree.
/// Hint: pointer to a node with parent=NULL is the pointer to wkv_t of the current tree.
struct wkv_t
{
    struct wkv_node_t root; ///< Base type.

    wkv_realloc_t realloc;
    wkv_free_t    free;

    void* context; ///< Can be assigned by the user code arbitrarily.
};

/// Use this to create a new Wild Key-Value instance. The context pointer can be set and mutated arbitrarily later.
static inline struct wkv_t wkv_init(const wkv_realloc_t realloc, const wkv_free_t free, void* const context)
{
    struct wkv_t out;
    memset(&out, 0, sizeof(struct wkv_t));
    out.root.parent  = NULL;
    out.root.edges   = NULL;
    out.root.payload = NULL;
    out.realloc      = realloc;
    out.free         = free;
    out.context      = context;
    return out;
}

/// Repeated separators are acceptable.
/// None of the pointers are allowed to be NULL.
/// Returns:
/// - Payload as-is on success.
/// - If this key is already known (not unique), the payload value of the existing key.
/// - NULL if out of memory.
/// Therefore, to check if the key is inserted successfully, compare the returned value against the original payload.
static inline void* wkv_add(struct wkv_t* const self, const char* const key, const char sep, void* const payload);

/// Returns the payload of the removed key if it was found, NULL if it didn't exist.
/// Accepts patterns, in which case all matching keys are removed and the payload of the last match is returned.
static inline void* wkv_remove(struct wkv_t* const self, const char* const pat, const char sep);

/// Find keys in the tree of keys that match the given wildcard pattern.
/// The pattern doesn't actually have to be a pattern, it can be an ordinary key name as well.
/// Searching stops when on_match returns a non-NULL value, which is then propagated back to the caller.
/// If no matches are found or on_match returns NULL for all matches, then NULL is returned.
static inline void* wkv_find_keys(struct wkv_t* const  self,
                                  const char* const    pat,
                                  const char           star,
                                  void* const          context,
                                  const wkv_on_match_t on_match);

/// Find wildcard patterns in the tree of patterns that match the given key.
/// Searching stops when on_match returns a non-NULL value, which is then propagated back to the caller.
/// If no matches are found or on_match returns NULL for all matches, then NULL is returned.
static inline void* wkv_find_pats(struct wkv_t* const  self,
                                  const char* const    key,
                                  const char           star,
                                  void* const          context,
                                  const wkv_on_match_t on_match);

/// A helper that obtains the wkv_t instance of the current tree from any of its nodes.
/// The complexity is linear of the maximum number of segments in any of the keys.
static inline struct wkv_t* wkv_get_self(struct wkv_node_t* node)
{
    WKV_ASSERT(node != NULL);
    while (node->parent != NULL) {
        node = node->parent;
    }
    return (struct wkv_t*)node;
}

// ----------------------------------------     END OF PUBLIC API SECTION      ----------------------------------------
// ----------------------------------------      POLICE LINE DO NOT CROSS      ----------------------------------------

static inline void _wkv_free(struct wkv_t* const self, void* const ptr)
{
    WKV_ASSERT(self != NULL);
    if (ptr != NULL) {
        self->free(self, ptr);
    }
}

/// Allocates the edge and its key segment in the same dynamically-sized memory block.
static struct wkv_edge_t* _wkv_edge_new(struct wkv_t* const      self,
                                        struct wkv_node_t* const parent,
                                        const size_t             seg_len,
                                        const char* const        seg)
{
    WKV_ASSERT(seg != NULL);
    struct wkv_edge_t* const edge =
      (struct wkv_edge_t*)self->realloc(self, NULL, offsetof(struct wkv_edge_t, seg) + seg_len + 1U);
    if (edge != NULL) {
        edge->node.parent  = parent;
        edge->node.n_edges = 0;
        edge->node.edges   = NULL;
        edge->node.payload = NULL;
        edge->seg_len      = seg_len;
        memcpy(&edge->seg[0], seg, seg_len);
        edge->seg[seg_len] = '\0';
    }
    return edge;
}

/// Binary search inside n->edge (which we keep sorted).
/// Returns negated (insertion point plus one) if the segment is not found.
static ptrdiff_t _wkv_bisect(struct wkv_node_t* const node, const size_t seg_len, const char* const seg)
{
    WKV_ASSERT((node != NULL) && (seg != NULL));
    size_t lo = 0;
    size_t hi = node->n_edges;
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2U;
        // ultra-fast comparison thanks to knowing the length of both segments
        const ptrdiff_t cmp = (seg_len == node->edges[mid]->seg_len)
                                ? memcmp(seg, node->edges[mid]->seg, seg_len)
                                : ((ptrdiff_t)seg_len - (ptrdiff_t)node->edges[mid]->seg_len);
        if (cmp == 0) {
            return (ptrdiff_t)mid;
        }
        if (cmp < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return -(((ptrdiff_t)lo) + 1); // insertion point; +1 is to handle the case of zero index insertion
}

static inline void _wkv_backtrack(struct wkv_t* const self, struct wkv_node_t* const node)
{
    WKV_ASSERT((self != NULL) && (node != NULL));
}

static inline void* wkv_add(struct wkv_t* const self, const char* const key, const char sep, void* const payload)
{
    if ((self == NULL) || (key == NULL) || (sep == '\0') || (payload == NULL)) {
        WKV_ASSERT(false);
        return NULL;
    }
    struct wkv_node_t* n             = &self->root;
    const char*        seg           = key;
    size_t             remaining_len = strnlen(seg, WKV_KEY_MAX_LEN);
    for (;;) {
        const char* const slash   = (const char*)memchr(seg, sep, remaining_len);
        const size_t      seg_len = (slash != NULL) ? (size_t)(slash - seg) : remaining_len;

        ptrdiff_t k = _wkv_bisect(n, seg_len, seg);
        if (k < 0) { // Insort the new edge.
            k = -(k + 1);
            WKV_ASSERT((k >= 0) && (k <= (ptrdiff_t)n->n_edges));
            // Expand the edge pointer array and allocate the new edge. This may fail, which will require backtracking.
            struct wkv_edge_t* new_e = NULL;
            {
                struct wkv_edge_t** const new_edges =
                  (struct wkv_edge_t**)self->realloc(self, n->edges, (n->n_edges + 1) * sizeof(struct wkv_edge_t*));
                if (new_edges != NULL) {  // Even if we bail later, we keep this larger array allocated as-is.
                    n->edges = new_edges; // It will be resized on node removal or insertion.
                    new_e    = _wkv_edge_new(self, n, seg_len, seg);
                }
            }
            if (NULL == new_e) {
                if (seg != key) { // otherwise, we haven't inserted anything yet
                    WKV_ASSERT(seg > key);
                    _wkv_backtrack(self, n);
                }
                return NULL;
            }
            WKV_ASSERT(n->edges != NULL);
            memmove(&n->edges[k + 1], &n->edges[k], (n->n_edges - (size_t)k) * sizeof(struct wkv_edge_t*));
            n->edges[k] = new_e;
            n->n_edges++;
        }
        WKV_ASSERT(n->edges != NULL);
        WKV_ASSERT(n == n->edges[k]->node.parent);
        n = &n->edges[k]->node;
        if (slash == NULL) {
            break;
        }
        seg = slash + 1;
        WKV_ASSERT(remaining_len > seg_len);
        remaining_len -= seg_len + 1;
    }
    WKV_ASSERT(n != NULL);
    // Do not overwrite the payload if it is already set. The caller will detect this by checking the return value.
    if (n->payload == NULL) {
        n->payload = payload;
    }
    return n->payload;
}

#ifdef __cplusplus
}
#endif

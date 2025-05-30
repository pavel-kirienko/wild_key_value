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

// ReSharper disable once CppUnusedIncludeDirective
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

#ifndef WKV_KEY_MAX_LEN
#define WKV_KEY_MAX_LEN 1024U
#endif

/// This can be overridden at runtime on a per-container basis.
#define WKV_DEFAULT_SEPARATOR '/'

/// A fundamental invariant of WKV is that every node has EITHER a value or outgoing edges.
struct wkv_node_t
{
    struct wkv_node_t*  parent; ///< NULL if this is the root node.
    size_t              n_edges;
    struct wkv_edge_t** edges; ///< Contiguous edge pointers ordered for bisection (ordering unspecified).
    void*               value; ///< NULL if this is not a full key.
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
/// Realloc is used to:
/// - Allocate new memory with the original pointer being NULL.
/// - To free memory when the size is zero.
/// - To resize the edges pointer array when entries are added/removed.
///
/// The semantics are per the standard realloc from stdlib, with one difference: if the fragment is reduced in size,
/// reallocation MUST succeed.
///
/// The recommended allocator is O1Heap: https://github.com/pavel-kirienko/o1heap
typedef void* (*wkv_realloc_t)(struct wkv_t* self, void* ptr, size_t new_size);

/// Internally, Wild Key-Value uses strings with explicit length for reasons of efficiency and safety.
/// User-supplied keys are converted to this format early.
struct wkv_str_t
{
    size_t      len; ///< Length of the string, excluding the trailing NUL.
    const char* str; ///< NUL-terminated string of length 'len'.
};

/// When a wildcard match occurs, the list of all segments that matched the wildcards in the query
/// is reported using this structure. The elements are ordered in the same way as they appear in the query.
/// For example, wildcard "/abc/*/def/**" matching "/abc/123/def/foo/456" produces the following substitution list:
/// 1. "123"
/// 2. "foo/456"
/// The length of the list equals the number of wildcards in the query.
struct wkv_substitution_t
{
    struct wkv_str_t           str;  ///< The string that matched the wildcard in the query is the base type.
    struct wkv_substitution_t* next; ///< Next substitution in the linked list, NULL if this is the last one.
};

struct wkv_match_t
{
    /// Full reconstructed key. Lifetime ends upon return from the match callback.
    struct wkv_str_t key;

    /// Substitutions that matched the corresponding wildcards in the query.
    /// NULL if there were no wildcards in the query.
    struct wkv_substitution_t* substitutions;

    /// The value associated with the key that matched the query.
    void* value;
};

/// Invoked on every wildcard match while searching. The value is guaranteed to be non-NULL.
///
/// Accepts not only the value but also the full key that matched the query.
/// TODO: pass substitutions that matched the wildcards in the query:
/// "/abc/123/def/foo/456" matching "/abc/*/def/**" produces "123" and "foo/456".
///
/// Searching stops when this function returns a non-NULL value, which is then propagated back to the caller.
/// The full key of the found match will be constructed on stack ad-hoc, so the lifetime of the key pointer
/// will end upon return from this function, but the value will obviously remain valid as long as the entry exists.
typedef void* (*wkv_on_match_t)(struct wkv_t* self, void* context, struct wkv_match_t match);

/// Once initialized, the instance shall not be moved or copied, as that breaks parent links in the tree.
/// Hint: pointer to a node with parent=NULL is the pointer to wkv_t of the current tree.
struct wkv_t
{
    struct wkv_node_t root; ///< Base type.

    /// Used to allocate, reallocate, and free memory for the tree nodes and edges.
    wkv_realloc_t realloc;

    /// Separator character used to split keys into segments. The default is WKV_DEFAULT_SEPARATOR.
    /// Can be changed to any non-zero character, but it should not be changed while the container is non-empty.
    char sep;

    void* context; ///< Can be assigned by the user code arbitrarily.
};

/// Use this to create a new Wild Key-Value instance. Once created, the instance must not be moved, unless empty.
static inline struct wkv_t wkv_init(const wkv_realloc_t realloc, void* const context)
{
    struct wkv_t out;
    memset(&out, 0, sizeof(struct wkv_t));
    out.root.parent = NULL;
    out.root.edges  = NULL;
    out.root.value  = NULL;
    out.realloc     = realloc;
    out.sep         = WKV_DEFAULT_SEPARATOR;
    out.context     = context;
    return out;
}

/// Repeated separators are acceptable. None of the pointers are allowed to be NULL.
/// Returns:
/// - Value as-is on success.
/// - If this key is already known (not unique), the value of the existing key.
/// - NULL if out of memory or key is longer than WKV_KEY_MAX_LEN.
/// Therefore, to check if the key is inserted successfully, compare the returned value against the original value.
static inline void* wkv_add(struct wkv_t* const self, const char* const key, void* const value);

/// This is like wkv_add, but it overwrites the existing value if the key already exists.
/// Returns:
/// - Value as-is on success.
/// - NULL if out of memory.
static inline void* wkv_set(struct wkv_t* const self, const char* const key, void* const value);

/// Find a key using literal matching, without wildcards. Every character in the key is treated verbatim.
/// NULL if no such key exists.
static inline void* wkv_get(const struct wkv_t* const self, const char* const key);

/// Removes the key using literal matching, without wildcards. Every character in the key is treated verbatim.
/// Returns the value of the removed key if it was found, NULL if it didn't exist.
static inline void* wkv_remove(struct wkv_t* const self, const char* const key);

/// Matching elements are reported in an unspecified order.
/// Searching stops when on_match returns a non-NULL value, which is then propagated back to the caller.
/// If no matches are found or on_match returns NULL for all matches, then NULL is returned.
static inline void* wkv_match(struct wkv_t* const  self,
                              const char* const    query,
                              const char           wild,
                              void* const          context,
                              const wkv_on_match_t on_match);

static inline bool wkv_is_empty(const struct wkv_t* const self)
{
    WKV_ASSERT((self != NULL) && (self->root.value == NULL));
    return self->root.n_edges == 0;
}

// ----------------------------------------     END OF PUBLIC API SECTION      ----------------------------------------
// ----------------------------------------      POLICE LINE DO NOT CROSS      ----------------------------------------

static inline void _wkv_free(struct wkv_t* const self, void* const ptr)
{
    WKV_ASSERT(self != NULL);
    if (ptr != NULL) {
        (void)self->realloc(self, ptr, 0);
    }
}

static inline struct wkv_str_t _wkv_key(const char* const str)
{
    WKV_ASSERT(str != NULL);
    struct wkv_str_t out;
    // Use max+1 to avoid truncating long keys, as that may cause an invalid key to match an existing valid key.
    out.len = strnlen(str, WKV_KEY_MAX_LEN + 1);
    out.str = str;
    return out;
}

/// Allocates the edge and its key segment in the same dynamically-sized memory block.
static struct wkv_edge_t* _wkv_edge_new(struct wkv_t* const      self,
                                        struct wkv_node_t* const parent,
                                        const struct wkv_str_t   seg)
{
    struct wkv_edge_t* const edge =
      (struct wkv_edge_t*)self->realloc(self, NULL, offsetof(struct wkv_edge_t, seg) + seg.len + 1U);
    if (edge != NULL) {
        edge->node.parent  = parent;
        edge->node.n_edges = 0;
        edge->node.edges   = NULL;
        edge->node.value   = NULL;
        edge->seg_len      = seg.len;
        memcpy(&edge->seg[0], seg.str, seg.len);
        edge->seg[seg.len] = '\0';
    }
    return edge;
}

/// Binary search inside n->edge (which we keep sorted).
/// Returns negated (insertion point plus one) if the segment is not found.
static ptrdiff_t _wkv_bisect(const struct wkv_node_t* const node, const size_t seg_len, const char* const seg)
{
    size_t lo = 0;
    size_t hi = node->n_edges;
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2U;
        // Ultra-fast comparison thanks to knowing the length of both segments.
        // IMPORTANT: because of the length comparison shortcut, the ordering is not lexicographic!
        // Rather, same-length segments are compared lexicographically, while shorter segments compare less than longer.
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

/// Returns the index of the edge pointing to this node in the parent's edge array.
/// If the node is the root, then -1 is returned.
static ptrdiff_t _wkv_locate_in_parent(struct wkv_node_t* const node)
{
    const struct wkv_node_t* const parent = node->parent;
    if (parent != NULL) {
        const struct wkv_edge_t* const edge = (struct wkv_edge_t*)node;
        const ptrdiff_t                k    = _wkv_bisect(parent, edge->seg_len, edge->seg);
        WKV_ASSERT((k >= 0) && (k < (ptrdiff_t)parent->n_edges));
        WKV_ASSERT(parent->edges[k] == edge);
        return k;
    }
    return -1; // The root node has no parent.
}

/// Downsize the edges pointer array of the node to the current number of edges.
/// Infallible because we require that realloc always succeeds when the size is non-increased.
static inline void _wkv_shrink(struct wkv_t* const self, struct wkv_node_t* const node)
{
    WKV_ASSERT((self != NULL) && (node != NULL));
    if (node->edges != NULL) {
        node->edges = (struct wkv_edge_t**)self->realloc(self, node->edges, node->n_edges * sizeof(struct wkv_edge_t*));
        WKV_ASSERT((node->edges != NULL) || (node->n_edges == 0));
    }
}

/// Starting from a leaf node, go up the tree and remove all nodes whose trace does not eventually lead to a full key.
/// This is intended for aborting insertions when we run out of memory and have to backtrack.
static inline void _wkv_prune_branch(struct wkv_t* const self, struct wkv_node_t* const node)
{
    WKV_ASSERT((self != NULL) && (node != NULL));
    _wkv_shrink(self, node);
    if ((node->n_edges == 0) && (node->value == NULL)) {
        const ptrdiff_t k = _wkv_locate_in_parent(node);
        if (k >= 0) {
            struct wkv_node_t* const p = node->parent;
            WKV_ASSERT(p != NULL);
            // Remove the edge from the parent's edge array. It will be shrunk in the next recursion level.
            p->n_edges--;
            memmove(&p->edges[k], &p->edges[k + 1], (p->n_edges - (size_t)k) * sizeof(struct wkv_edge_t*));
            // Free the edge and its segment. We use the node pointer which is the same as the edge pointer.
            _wkv_free(self, node->edges); // This is probably NULL bc empty, but we don't enforce this.
            _wkv_free(self, node);
            // Removing the node from the parent may have caused the parent to become eligible for garbage collection.
            _wkv_prune_branch(self, p);
        }
        // If the node is not eligible for garbage collection, then all its parents are not eligible either,
        // which means there is nothing left to do.
    }
}

static inline struct wkv_node_t* _wkv_insert(struct wkv_t* const self, const struct wkv_str_t key)
{
    if ((self == NULL) || (self->sep == '\0')) {
        WKV_ASSERT(false);
        return NULL;
    }
    if (key.len > WKV_KEY_MAX_LEN) {
        return NULL;
    }
    struct wkv_node_t* n                 = &self->root;
    size_t             remaining_key_len = key.len;
    struct wkv_str_t   seg               = key;
    for (;;) {
        const char* const slash = (const char*)memchr(seg.str, self->sep, remaining_key_len);
        seg.len                 = (slash != NULL) ? (size_t)(slash - seg.str) : remaining_key_len;
        ptrdiff_t k             = _wkv_bisect(n, seg.len, seg.str);
        if (k < 0) { // Insort the new edge.
            k = -(k + 1);
            WKV_ASSERT((k >= 0) && (k <= (ptrdiff_t)n->n_edges));
            // Expand the edge pointer array and allocate the new edge. This may fail, which will require backtracking.
            struct wkv_edge_t* new_e = NULL;
            {
                struct wkv_edge_t** const new_edges =
                  (struct wkv_edge_t**)self->realloc(self, n->edges, (n->n_edges + 1) * sizeof(struct wkv_edge_t*));
                if (new_edges != NULL) {
                    n->edges = new_edges; // Will be shrunk later if necessary.
                    new_e    = _wkv_edge_new(self, n, seg);
                }
            }
            if (NULL == new_e) {
                _wkv_prune_branch(self, n); // We may have inserted transient nodes that are now garbage. Clean them up.
                return NULL;
            }
            WKV_ASSERT(n->edges != NULL);
            memmove(&n->edges[k + 1], &n->edges[k], (n->n_edges - (size_t)k) * sizeof(struct wkv_edge_t*));
            n->edges[k] = new_e;
            n->n_edges++;
        }
        WKV_ASSERT((n->edges != NULL) && (n == n->edges[k]->node.parent));
        n = &n->edges[k]->node;
        if (slash == NULL) {
            break;
        }
        seg.str = slash + 1;
        WKV_ASSERT(remaining_key_len > seg.len);
        remaining_key_len -= seg.len + 1;
    }
    WKV_ASSERT(n != NULL);
    return n;
}

static inline void* wkv_add(struct wkv_t* const self, const char* const key, void* const value)
{
    struct wkv_node_t* const n = _wkv_insert(self, _wkv_key(key));
    if (n != NULL) {
        if (n->value == NULL) {
            n->value = value; // Assign the value only if this is a new key.
        }
        return n->value;
    }
    return NULL;
}

static inline void* wkv_set(struct wkv_t* const self, const char* const key, void* const value)
{
    struct wkv_node_t* const n = _wkv_insert(self, _wkv_key(key));
    if (n != NULL) {
        n->value = value; // Assign the value regardless of whether this is a new key or not.
        return n->value;
    }
    return NULL;
}

static inline struct wkv_node_t* _wkv_get(const struct wkv_t* const      self,
                                          const struct wkv_node_t* const node,
                                          struct wkv_str_t               key)
{
    if ((self == NULL) || (self->sep == '\0')) {
        WKV_ASSERT(false);
        return NULL;
    }
    const char* const  slash   = (const char*)memchr(key.str, self->sep, key.len);
    const size_t       seg_len = (slash != NULL) ? (size_t)(slash - key.str) : key.len;
    const bool         is_last = (slash == NULL);
    struct wkv_node_t* result  = NULL;
    const ptrdiff_t    k       = _wkv_bisect(node, seg_len, key.str);
    if (k >= 0) {
        WKV_ASSERT((size_t)k < node->n_edges);
        struct wkv_edge_t* const edge = node->edges[k];
        WKV_ASSERT((edge != NULL) && (edge->node.parent == node));
        if (is_last) {
            result = &edge->node;
        } else {
            key.len -= seg_len + 1;
            key.str = slash + 1;
            result  = _wkv_get(self, &edge->node, key);
        }
    }
    return result;
}

static inline void* wkv_get(const struct wkv_t* const self, const char* const key)
{
    const struct wkv_node_t* const node = _wkv_get(self, &self->root, _wkv_key(key));
    return (node != NULL) ? node->value : NULL;
}

static inline void* wkv_remove(struct wkv_t* const self, const char* const key)
{
    struct wkv_node_t* const node  = _wkv_get(self, &self->root, _wkv_key(key));
    void*                    value = NULL;
    if (node != NULL) {
        value       = node->value;
        node->value = NULL;
        _wkv_prune_branch(self, node);
    }
    return value;
}

/// Ascend the tree and copy the full key leading to the current node into the buffer.
static inline void _wkv_gather_key(const struct wkv_node_t* node, const size_t key_len, const char sep, char* const buf)
{
    WKV_ASSERT(key_len <= WKV_KEY_MAX_LEN);
    char* p    = &buf[key_len];
    *p         = '\0';
    bool first = true;
    while (node->parent != NULL) {
        WKV_ASSERT(node->parent->n_edges > 0);
        if (!first) {
            *--p = sep;
        }
        first                               = false;
        const struct wkv_edge_t* const edge = (const struct wkv_edge_t*)node;
        WKV_ASSERT(edge->seg_len <= key_len);
        p -= edge->seg_len;
        WKV_ASSERT(p >= buf);
        memcpy(p, edge->seg, edge->seg_len);
        node = node->parent;
    }
    WKV_ASSERT((buf[key_len] == '\0') && (p == buf) && (strlen(p) == key_len));
}

struct _wkv_find_all_context_t
{
    struct wkv_t*  self;
    size_t         key_len;
    void*          context;
    char           wild;
    wkv_on_match_t on_match;
};

static inline void* _wkv_on_match_maybe(const struct _wkv_find_all_context_t* const ctx,
                                        const struct wkv_node_t* const              node)
{
    void* result = NULL;
    if (node->value != NULL) {
        WKV_ASSERT(ctx->key_len <= WKV_KEY_MAX_LEN);
        char buf[1 +
#ifdef __cplusplus
                 WKV_KEY_MAX_LEN
#else
                 key_len
#endif
        ];
        _wkv_gather_key(node, ctx->key_len, ctx->self->sep, buf);
        struct wkv_match_t match;
        match.key.len       = ctx->key_len;
        match.key.str       = buf;
        match.substitutions = NULL; // TODO: implement substitutions
        match.value         = node->value;
        result              = ctx->on_match(ctx->self, ctx->context, match);
    }
    return result;
}

static inline void* _wkv_find_all(struct _wkv_find_all_context_t* const ctx,
                                  const struct wkv_node_t* const        node,
                                  const size_t                          query_len,
                                  const char* const                     query)
{
    const char* const slash        = (const char*)memchr(query, ctx->self->sep, query_len);
    const size_t      seg_len      = (slash != NULL) ? (size_t)(slash - query) : query_len;
    const bool        is_last      = (slash == NULL);
    const char* const next_seg     = is_last ? NULL : (slash + 1);
    const size_t      next_seg_len = is_last ? 0 : (query_len - seg_len - 1);
    void*             result       = NULL;
    if (is_last && (seg_len == 2) && (query[0] == ctx->wild) && (query[1] == ctx->wild)) {
        // Recursive wildcard placed at the end matches everything down the tree.
        assert(false);
    } else if ((seg_len == 1) && (query[0] == ctx->wild)) { // Single-segment substitution.
        assert(false);
    } else {
        const ptrdiff_t k = _wkv_bisect(node, seg_len, query);
        if (k >= 0) {
            WKV_ASSERT((size_t)k < node->n_edges);
            const struct wkv_edge_t* const edge = node->edges[k];
            WKV_ASSERT((edge != NULL) && (edge->node.parent == node));
            if (is_last) {
                result = _wkv_on_match_maybe(ctx, &edge->node);
            } else {
                result = _wkv_find_all(ctx, &edge->node, next_seg_len, next_seg);
            }
        }
    }
    return result;
}

static inline void* wkv_match(struct wkv_t* const  self,
                              const char* const    query,
                              const char           wild,
                              void* const          context,
                              const wkv_on_match_t on_match)
{
    if ((self == NULL) || (query == NULL) || (self->sep == '\0') || (wild == '\0') || (on_match == NULL)) {
        WKV_ASSERT(false);
        return NULL;
    }
    struct _wkv_find_all_context_t ctx;
    ctx.self     = self;
    ctx.key_len  = strnlen(query, WKV_KEY_MAX_LEN);
    ctx.context  = context;
    ctx.wild     = wild;
    ctx.on_match = on_match;
    // Use max+1 to avoid truncating long keys, as that may cause an invalid key to match an existing valid key.
    return _wkv_find_all(&ctx, &self->root, strnlen(query, WKV_KEY_MAX_LEN + 1), query);
}

#ifdef __cplusplus
}
#endif

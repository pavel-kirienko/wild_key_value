/// Source: https://github.com/pavel-kirienko/wild_key_value
///
/// Wild Key-Value (WKV) is a very fast and very simple key-value container for embedded systems
/// that supports wildcard lookup. The keys are strings, and the values are user-provided void pointers.
/// Keys are stored in the heap in fragments; common prefixes are deduplicated.
/// The container is designed for very fast logarithmic lookup and insertion, and is extremely frugal with memory.
/// The recommended memory manager is O1Heap, which offers low worst-case fragmentation and constant allocation time.
///
/// Basic usage:
///
///     wkv_t kv = wkv_init(realloc_function);
///
///     // Set some keys:
///     void* val = wkv_set(&kv, "foo/bar", my_bar);
///     if (val == nullptr) { /* OOM or key too long */ }
///     val = wkv_set(&kv, "foo/baz", my_baz);
///     if (val == nullptr) { ... }
///     assert(wkv_get(&kv, "foo/bar") == my_bar);
///
///     // Overwrite a key:
///     void* val = wkv_set(&kv, "foo/bar", my_zoo);
///     if (val == nullptr) { /* Key did not exist and insertion caused OOM, or key too long */ }
///     assert(wkv_get(&kv, "foo/bar") == my_zoo);
///
///     // Erase a key:
///     void* val = wkv_set(&kv, "foo/bar", nullptr);
///     if (val == nullptr) { /* Key did not exist */ }
///     else { /* Key existed and was erased; its old value is returned. */ }
///
/// See also:
/// - Cavl <https://github.com/pavel-kirienko/cavl> -- a single-header, efficient and robust AVL tree implementation.
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

/// Internally, Wild Key-Value uses strings with explicit length for reasons of efficiency and safety.
/// User-supplied keys are converted to this format early.
struct wkv_str_t
{
    size_t      len; ///< Length of the string, excluding the trailing NUL.
    const char* str; ///< NUL-terminated string of length 'len'.
};

/// A fundamental invariant of WKV is that every node has a value or outgoing edges. Nodes with neither are removed.
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
/// Each node takes one allocation, unless it has no outgoing edges; each edge takes one allocation always.
/// Per-edge allocation is of size sizeof(struct wkv_node_t) + sizeof(size_t) + strlen(key_segment) + 1.
/// Per-node allocation is of size n_edges * sizeof(pointer).
///
/// Realloc is used to:
/// - Allocate new memory with the original pointer being NULL.
/// - To free memory when the size is zero.
/// - To resize the edges pointer array when entries are added/removed.
///
/// The semantics are per the standard realloc from stdlib, except:
/// - If the fragment is not increased in size, reallocation MUST succeed.
/// - If the size is zero, it must behave like free() (which is often the case but technically an UB).
///
/// The recommended allocator is O1Heap: https://github.com/pavel-kirienko/o1heap
typedef void* (*wkv_realloc_t)(struct wkv_t* self, void* ptr, size_t new_size);

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

// ----------------------------------------    INIT AND AUXILIARY FUNCTIONS    ----------------------------------------

/// Use this to create a new Wild Key-Value instance. Once created, the instance must not be moved, unless empty.
static inline struct wkv_t wkv_init(const wkv_realloc_t realloc)
{
    struct wkv_t out;
    memset(&out, 0, sizeof(struct wkv_t));
    out.root.parent = NULL;
    out.root.edges  = NULL;
    out.root.value  = NULL;
    out.realloc     = realloc;
    out.sep         = WKV_DEFAULT_SEPARATOR;
    out.context     = NULL;
    return out;
}

static inline bool wkv_is_empty(const struct wkv_t* const self)
{
    WKV_ASSERT((self != NULL) && (self->root.value == NULL));
    return self->root.n_edges == 0;
}

// ----------------------------------------    SET/GET/DEL, VERBATIM KEYS    ----------------------------------------

/// If the key is non-NULL, a new entry is created with the specified key and value, unless one already exists.
/// If the key is NULL, the item with this key will be removed from the container; no effect if the key does not exist.
/// Returns:
/// - On insertion: value as-is on success; on removal: old value on success, or NULL if the key did not exist.
/// - If this key is already known (not unique), the value of the existing key.
/// - NULL if out of memory or key is longer than WKV_KEY_MAX_LEN.
/// Therefore, to check if the key is inserted successfully, compare the returned value against the original value.
/// Complexity is logarithmic in the number of keys in the container.
static inline void* wkv_add(struct wkv_t* const self, const char* const key, void* const value);

/// This is like wkv_add, but it overwrites the existing value if the key already exists.
/// Removal on NULL value works the same as in wkv_add.
/// Returns:
/// - On insertion: value as-is on success; on removal: old value on success, or NULL if the key did not exist.
/// - NULL if out of memory.
static inline void* wkv_set(struct wkv_t* const self, const char* const key, void* const value);

/// Find a key using literal matching (without wildcards). Every character in the key is treated verbatim.
/// NULL if no such key exists.
/// Complexity is logarithmic in the number of keys in the container.
static inline void* wkv_get(const struct wkv_t* const self, const char* const key);

/// Returns the value and key of the element at the specified index in an unspecified order.
///
/// The key storage must be at least WKV_KEY_MAX_LEN + 1 bytes large; key_len points to the actual length of
/// the key buffer, not including the trailing NUL; it will be set to the length of the key that was returned.
/// If key or key_len are NULL, or if the key buffer is too small, then the key will not be returned.
/// To check if the key was returned, set key_len to WKV_KEY_MAX_LEN+1 and then check key_len<=WKV_KEY_MAX_LEN.
///
/// If the index is out of bounds, then NULL is returned.
/// The complexity is linear in the number of keys in the container! This is not the primary way to access keys!
static inline void* wkv_at(struct wkv_t* const self, size_t index, char* const key, size_t* const key_len);

// ----------------------------------------          WILDCARD KEY API          ----------------------------------------

/// A wildcard is a pattern that contains substitution symbols. WKV currently recognizes two types of substitutions:
///
/// Single segment substitution: "/abc/*/def" -- matches "/abc/123/def", with "123" being the substitution.
/// The single-segment substitution symbol must be the only symbol in the segment;
/// otherwise, the segment is treated as a literal (matches only itself).
///
/// Recursive substitution: "abc/**" -- matches everything with the "abc/" prefix, e.g. "abc/123/456/789".
/// The recursive substitution pattern can only occur at the end of the pattern;
/// otherwise, it is treated as a literal (matches only itself).
/// It obviously follows that there may be at most one recursive substitution in the pattern.
///
/// When a wildcard match occurs, the list of all substitution patterns that matched the corresponding query segments
/// is reported using this structure. The elements are ordered in the same way as they appear in the query.
/// For example, pattern "abc/*/def/**" matching "abc/123/def/foo/456/xyz" produces the following substitution list:
/// 1. "123"  <-- from the first *
/// 2. "foo"  <-- this and the following come from **.
/// 3. "456"
/// 4. "xyz"
///
/// If the pattern contains only non-recursive substitutions, then the number of substitutions equals the number of
/// substitution segments in the query. If a recursive substitution is present, then the number of substitutions
/// may be greater.
struct wkv_substitution_t
{
    struct wkv_str_t           str;  ///< The string that matched the wildcard in the query is the base type.
    struct wkv_substitution_t* next; ///< Next substitution in the linked list, NULL if this is the last one.
};

/// The lifetime of all pointers except value ends upon return from the match callback.
struct wkv_match_t
{
    /// Full reconstructed key. Lifetime ends upon return from the match callback.
    /// Iff key reconstruction is disabled, this will have a NULL str pointer and len==0.
    struct wkv_str_t key;

    /// Substitutions that matched the corresponding wildcards in the query.
    /// NULL if there were no wildcards in the query.
    const struct wkv_substitution_t* substitutions;

    /// The value associated with the key that matched the query.
    void* value;
};

/// Invoked on every wildcard match while searching. The value is guaranteed to be non-NULL.
///
/// Accepts not only the value but also the full key that matched the query,
/// plus substitutions that matched the wildcards in the query.
///
/// Searching stops when this function returns a non-NULL value, which is then propagated back to the caller.
/// The full key of the found match will be constructed on stack ad-hoc, so the lifetime of the key pointer
/// will end upon return from this function, but the value will obviously remain valid as long as the entry exists.
typedef void* (*wkv_on_match_t)(struct wkv_t* self, void* context, struct wkv_match_t match);

/// Matching elements are reported in an unspecified order.
///
/// Searching stops when on_match returns a non-NULL value, which is then propagated back to the caller.
/// If no matches are found or on_match returns NULL for all matches, then NULL is returned.
///
/// key_reconstruction_buffer may be NULL if the matched keys are not of interest; otherwise, it must point
/// to a storage of at least WKV_KEY_MAX_LEN+1 bytes. Key reconstruction adds extra processing per reported key
/// which is linearly dependent on the key length.
static inline void* wkv_match(struct wkv_t* const  self,
                              const char* const    pattern,
                              const char           wild,
                              char* const          key_reconstruction_buffer,
                              void* const          context,
                              const wkv_on_match_t on_match);

// ====================================================================================================================
// ----------------------------------------     END OF PUBLIC API SECTION      ----------------------------------------
// ====================================================================================================================
// ----------------------------------------      POLICE LINE DO NOT CROSS      ----------------------------------------
// ====================================================================================================================

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

static inline struct wkv_str_t _wkv_edge_seg(const struct wkv_edge_t* const edge)
{
    WKV_ASSERT(edge != NULL);
    struct wkv_str_t out;
    out.len = edge->seg_len;
    out.str = edge->seg;
    return out;
}

struct _wkv_split_t
{
    struct wkv_str_t head;
    struct wkv_str_t tail;
    bool             last;
};

static inline struct _wkv_split_t _wkv_split(const struct wkv_str_t key, const char sep)
{
    const char* const   slash   = (const char*)memchr(key.str, sep, key.len);
    const size_t        seg_len = (slash != NULL) ? (size_t)(slash - key.str) : key.len;
    struct _wkv_split_t out;
    out.head.str = key.str;
    out.head.len = seg_len;
    out.tail.str = (slash != NULL) ? (slash + 1) : NULL;
    out.tail.len = (slash != NULL) ? (key.len - seg_len - 1U) : 0U;
    out.last     = (slash == NULL);
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
static ptrdiff_t _wkv_bisect(const struct wkv_node_t* const node, const struct wkv_str_t seg)
{
    size_t lo = 0;
    size_t hi = node->n_edges;
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2U;
        // Ultra-fast comparison thanks to knowing the length of both segments.
        // IMPORTANT: because of the length comparison shortcut, the ordering is not lexicographic!
        // Rather, same-length segments are compared lexicographically, while shorter segments compare less than longer.
        const ptrdiff_t cmp = (seg.len == node->edges[mid]->seg_len)
                                ? memcmp(seg.str, node->edges[mid]->seg, seg.len)
                                : ((ptrdiff_t)seg.len - (ptrdiff_t)node->edges[mid]->seg_len);
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
        const ptrdiff_t                k    = _wkv_bisect(parent, _wkv_edge_seg(edge));
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
    if (key.len > WKV_KEY_MAX_LEN) {
        return NULL;
    }
    struct wkv_node_t*  n = &self->root;
    struct _wkv_split_t x;
    x.tail = key; // Start with the full key.
    do {
        x           = _wkv_split(x.tail, self->sep);
        ptrdiff_t k = _wkv_bisect(n, x.head);
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
                    new_e    = _wkv_edge_new(self, n, x.head);
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
    } while (!x.last);
    WKV_ASSERT(n != NULL);
    return n;
}

static inline struct wkv_node_t* _wkv_get(const struct wkv_t* const      self,
                                          const struct wkv_node_t* const node,
                                          const struct wkv_str_t         key)
{
    struct wkv_node_t*        result = NULL;
    const struct _wkv_split_t x      = _wkv_split(key, self->sep);
    const ptrdiff_t           k      = _wkv_bisect(node, x.head);
    if (k >= 0) {
        WKV_ASSERT((size_t)k < node->n_edges);
        struct wkv_edge_t* const edge = node->edges[k];
        WKV_ASSERT((edge != NULL) && (edge->node.parent == node));
        result = x.last ? &edge->node : _wkv_get(self, &edge->node, x.tail);
    }
    return result;
}

static inline void* _wkv_del(struct wkv_t* const self, const struct wkv_str_t key)
{
    struct wkv_node_t* const node  = _wkv_get(self, &self->root, key);
    void*                    value = NULL;
    if (node != NULL) {
        value       = node->value;
        node->value = NULL;
        _wkv_prune_branch(self, node);
    }
    return value;
}

static inline void* wkv_add(struct wkv_t* const self, const char* const key, void* const value)
{
    const struct wkv_str_t k      = _wkv_key(key);
    void*                  result = NULL;
    if (value != NULL) {
        struct wkv_node_t* const n = _wkv_insert(self, k);
        if (n != NULL) {
            if (n->value == NULL) {
                n->value = value; // Assign the value only if this is a new key.
            }
            result = n->value;
        }
    } else {
        result = _wkv_del(self, k);
    }
    return result;
}

static inline void* wkv_set(struct wkv_t* const self, const char* const key, void* const value)
{
    const struct wkv_str_t k      = _wkv_key(key);
    void*                  result = NULL;
    if (value != NULL) {
        struct wkv_node_t* const n = _wkv_insert(self, k);
        if (n != NULL) {
            n->value = value; // Assign the value regardless of whether this is a new key or not.
            result   = n->value;
        }
    } else {
        result = _wkv_del(self, k);
    }
    return result;
}

static inline void* wkv_get(const struct wkv_t* const self, const char* const key)
{
    const struct wkv_str_t         k    = _wkv_key(key);
    const struct wkv_node_t* const node = _wkv_get(self, &self->root, k);
    return (node != NULL) ? node->value : NULL;
}

/// Ascend the tree and copy the full key leading to the current node into the buffer.
static inline struct wkv_str_t _wkv_reconstruct_key(const struct wkv_node_t* node,
                                                    const size_t             key_len,
                                                    const char               sep,
                                                    char* const              buf)
{
    WKV_ASSERT(key_len <= WKV_KEY_MAX_LEN);
    char* p = &buf[key_len];
    *p      = '\0';
    while (node->parent != NULL) {
        WKV_ASSERT(node->parent->n_edges > 0);
        const struct wkv_edge_t* const edge = (const struct wkv_edge_t*)node;
        WKV_ASSERT(edge->seg_len <= key_len);
        p -= edge->seg_len;
        WKV_ASSERT(p >= buf);
        memcpy(p, edge->seg, edge->seg_len);
        node = node->parent;
        if (node->parent != NULL) {
            *--p = sep;
        }
    }
    WKV_ASSERT((buf[key_len] == '\0') && (p == buf) && (strlen(p) == key_len));
    const struct wkv_str_t out = { key_len, p };
    return out;
}

static inline struct wkv_node_t* _wkv_at(struct wkv_node_t* const node,
                                         size_t* const            index,
                                         const size_t             prefix_len,
                                         size_t* const            out_key_len)
{
    if (node->value != NULL) {
        if (*index == 0) {
            *out_key_len = prefix_len - 1; // Remove trailing separator.
            return node;
        }
        --*index;
    }
    for (size_t i = 0; i < node->n_edges; ++i) {
        struct wkv_node_t* const child = _wkv_at(&node->edges[i]->node, //
                                                 index,
                                                 prefix_len + node->edges[i]->seg_len + 1, // +1 for the separator
                                                 out_key_len);
        if (child != NULL) {
            return child;
        }
    }
    return NULL;
}

static inline void* wkv_at(struct wkv_t* const self, size_t index, char* const key, size_t* const key_len)
{
    void*                          result        = NULL;
    size_t                         key_len_local = WKV_KEY_MAX_LEN + 1; // sentinel
    const struct wkv_node_t* const node          = _wkv_at(&self->root, &index, 0, &key_len_local);
    if (node != NULL) {
        WKV_ASSERT(node->value != NULL);
        WKV_ASSERT(key_len_local <= WKV_KEY_MAX_LEN);
        result = node->value;
        if ((key != NULL) && (key_len != NULL) && (key_len_local <= *key_len)) {
            *key_len = key_len_local;
            (void)_wkv_reconstruct_key(node, key_len_local, self->sep, key);
        }
    }
    return result;
}

// ----------------------------------------        FAST PATTERN MATCHER         ----------------------------------------

struct _wkv_matcher_event_t
{
    struct wkv_node_t*        node;
    size_t                    key_len;
    const wkv_substitution_t* substitutions; ///< NULL if there are no wildcards in the query.
};

/// Invoked when a wildcard match occurs, EVEN IF THE NODE IS VALUELESS.
typedef void* (*_wkv_matcher_cb_t)(const struct _wkv_matcher_t*, struct _wkv_matcher_event_t);

struct _wkv_matcher_t
{
    struct wkv_t*     self;
    char              wild;
    _wkv_matcher_cb_t cb;
};

/// Attempts to match the pattern against all nodes, even valueless ones, and reports them to the callback.
/// If you want to hand it over to the user, ensure the node is not valueless first!
///
/// Currently, we DO NOT support wildcard removal of nodes from the callback, for the sole reason that removal
/// would invalidate our edges traversal state. This can be doctored, if necessary.
/// One way to do this is to copy the edge pointer array on the stack before traversing it.
/// Another solution is to bubble up the removal flag to the traversal function so that we can reuse the same
/// index for the next iteration.
static inline void* _wkv_matcher_descend(const struct _wkv_matcher_t* const ctx,
                                         const struct wkv_node_t* const     node,
                                         const struct wkv_str_t             pattern,
                                         const size_t                       prefix_len,
                                         const wkv_substitution_t* const    sub_head,
                                         wkv_substitution_t* const          sub_tail);

static inline void* _wkv_matcher_descend_all(const struct _wkv_matcher_t* const ctx,
                                             const struct wkv_node_t* const     node,
                                             const struct wkv_str_t             next_seg,
                                             const bool                         recurse,
                                             const size_t                       prefix_len,
                                             const wkv_substitution_t* const    sub_head,
                                             wkv_substitution_t* const          sub_tail)
{
    void* result = NULL;
    for (size_t i = 0; (i < node->n_edges) && (result == NULL); ++i) {
        struct wkv_edge_t* const edge = node->edges[i];

        // Create a new substitution for the current edge segment and link it into the list.
        struct wkv_substitution_t        sub          = { _wkv_edge_seg(edge), NULL };
        const struct wkv_substitution_t* sub_head_new = (sub_head == NULL) ? &sub : sub_head;
        if (sub_tail != NULL) {
            sub_tail->next = &sub;
        }

        const struct _wkv_matcher_event_t evt = { &edge->node, prefix_len + edge->seg_len, sub_head_new };
        if (!recurse) {
            result = (next_seg.str == NULL)
                       ? ctx->cb(ctx, evt)
                       : _wkv_matcher_descend(ctx, evt.node, next_seg, evt.key_len + 1, sub_head_new, &sub);
        } else {
            WKV_ASSERT(next_seg.str == NULL);
            result = ctx->cb(ctx, evt);
            if (result == NULL) {
                result = _wkv_matcher_descend_all(ctx, evt.node, next_seg, true, evt.key_len + 1, sub_head_new, &sub);
            }
        }
    }
    return result;
}

static inline void* _wkv_matcher_descend_one(const struct _wkv_matcher_t* const ctx,
                                             const struct wkv_node_t* const     node,
                                             const struct _wkv_split_t          x,
                                             const size_t                       prefix_len,
                                             const wkv_substitution_t* const    sub_head,
                                             wkv_substitution_t* const          sub_tail)
{
    void*           result = NULL;
    const ptrdiff_t k      = _wkv_bisect(node, x.head);
    if (k >= 0) { // otherwise, no match on this subtree.
        struct wkv_edge_t* const    edge = node->edges[k];
        struct _wkv_matcher_event_t evt;
        evt.node          = &edge->node;
        evt.key_len       = prefix_len + edge->seg_len;
        evt.substitutions = sub_head;
        result            = x.last //
                              ? ctx->cb(ctx, evt)
                              : _wkv_matcher_descend(ctx, evt.node, x.tail, evt.key_len + 1, sub_head, sub_tail);
    }
    return result;
}

static inline void* _wkv_matcher_descend(const struct _wkv_matcher_t* const ctx,
                                         const struct wkv_node_t* const     node,
                                         const struct wkv_str_t             pattern,
                                         const size_t                       prefix_len,
                                         const wkv_substitution_t* const    sub_head,
                                         wkv_substitution_t* const          sub_tail)
{
    const struct _wkv_split_t x = _wkv_split(pattern, ctx->self->sep);
    const bool                wild_recurse =
      x.last && (x.head.len == 2) && (x.head.str[0] == ctx->wild) && (x.head.str[1] == ctx->wild);
    const bool wild_segment = (x.head.len == 1) && (x.head.str[0] == ctx->wild);
    return (wild_segment || wild_recurse)
             ? _wkv_matcher_descend_all(ctx, node, x.tail, wild_recurse, prefix_len, sub_head, sub_tail)
             : _wkv_matcher_descend_one(ctx, node, x, prefix_len, sub_head, sub_tail);
}

// ----------------------------------------            wkv_match            ----------------------------------------

struct _wkv_match_context_t
{
    struct _wkv_matcher_t base;
    char*                 key_reconstruction_buffer;
    void*                 context;
    wkv_on_match_t        on_match;
};

static inline void* _wkv_match_cb_adapter(const struct _wkv_matcher_t* const ctx, const struct _wkv_matcher_event_t evt)
{
    void* result = NULL;
    if (evt.node->value != NULL) {
        const struct _wkv_match_context_t* const cast = (struct _wkv_match_context_t*)ctx;
        WKV_ASSERT(evt.key_len <= WKV_KEY_MAX_LEN);
        struct wkv_match_t match = { { 0, NULL }, evt.substitutions, evt.node->value };
        if (cast->key_reconstruction_buffer != NULL) {
            match.key = _wkv_reconstruct_key(evt.node, evt.key_len, ctx->self->sep, cast->key_reconstruction_buffer);
        }
        result = cast->on_match(ctx->self, cast->context, match);
    }
    return result;
}

static inline void* wkv_match(struct wkv_t* const  self,
                              const char* const    pattern,
                              const char           wild,
                              char* const          key_reconstruction_buffer,
                              void* const          context,
                              const wkv_on_match_t on_match)
{
    const struct _wkv_match_context_t ctx = {
        { self, wild, _wkv_match_cb_adapter }, key_reconstruction_buffer, context, on_match
    };
    return _wkv_matcher_descend(&ctx.base, &self->root, _wkv_key(pattern), 0, NULL, NULL);
}

#ifdef __cplusplus
}
#endif

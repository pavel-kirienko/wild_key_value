/// Source: https://github.com/pavel-kirienko/wild_key_value
///
/// Wild Key-Value (WKV) is a very fast and very simple single-header key-value container for embedded systems
/// that supports wildcard lookup. The keys are strings, and the values are void pointers.
/// Keys are stored in the heap in fragments; common prefixes are deduplicated so the memory usage is minimized.
///
/// The container is designed for very fast logarithmic lookup and insertion (roughly comparable to std::map),
/// and is extremely frugal with memory. Internally, it uses bisection comparing key segments by length first
/// (shorter compares smaller), then lexicographically; this is important in some applications.
///
/// The recommended memory manager is O1Heap, which offers constant allocation time and low worst-case fragmentation,
/// but it works with any other heap (incl. the standard heap) as well.
///
/// Usage:
///
///     #include <wkv.h>
///
///     wkv_t kv = wkv_init(realloc_function);
///
///     // Create some keys:
///     void* val = wkv_set(&kv, "foo/bar", my_bar);
///     if (val == nullptr) { /* OOM or key too long */ }
///     val = wkv_set(&kv, "foo/baz", my_baz);
///     if (val == nullptr) { ... }
///     assert(wkv_get(&kv, "foo/bar") == my_bar);  // Yup, the key is there.
///     // Note: '/' is the default key segment separator, but it can be changed at runtime.
///
///     // Existing keys can be overwritten:
///     void* val = wkv_set(&kv, "foo/bar", my_zoo);
///     if (val == nullptr) { /* Key did not exist and insertion caused OOM, or key too long */ }
///     assert(wkv_get(&kv, "foo/bar") == my_zoo);  // Yup, the key was overwritten.
///
///     // Access keys by index in an unspecified order:
///     char key_buf[WKV_KEY_MAX_LEN + 1];
///     size_t key_len = sizeof(key_buf);
///     void* val = wkv_at(&kv, 0, key_buf, &key_len);
///     if (val == nullptr) { /* Index out of range. */ }
///     else {
///         // Key is in key_buf, key length in key_len, and its value is in val.
///         printf("key: '%s', value: %p\n", key_buf, val);
///     }
///
///     // To erase a key, set its value to NULL:
///     void* val = wkv_set(&kv, "foo/bar", nullptr);
///     if (val == nullptr) { /* Key did not exist */ }
///     else {
///         // Key existed and was erased; its old value is returned.
///         // This is a valid usage pattern, too: free(wkv_set(&kv, "foo/bar", nullptr));
///     }
///
///     // Important: an empty key segment is also a valid key segment. This simple rule implies that:
///     // - Repeated separators are not coalesced but treated verbatim -- distinct strings are distinct keys, always.
///     // - An empty string is also a valid key.
///     // Normalization is out of the scope of this library.
///     // All statements below are valid and create distinct keys:
///     wkv_set(&kv, "a/b",  my_value);
///     wkv_set(&kv, "a//b", my_value);
///     wkv_set(&kv, "/a/b", my_value);
///     wkv_set(&kv, "a/b/", my_value);
///     wkv_set(&kv, "/",    my_value);
///     wkv_set(&kv, "//",   my_value);
///     wkv_set(&kv, "",     my_value);
///
/// Example realloc_function using the standard heap (for o1heap it would look similar):
///
///     static void* realloc_function(struct wkv_t* const self, void* const ptr, const size_t new_size)
///     {
///         if (new_size > 0) { return realloc(ptr, new_size); }
///         free(ptr);  // Handle freeing explicitly because invoking the standard realloc() with zero size is UB.
///         return NULL;
///     }
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

// TODO BETTER DOCS

/// The default maximum key length is chosen rather arbitrarily. It does not affect the memory consumption or
/// performance within the container, but it is needed to enforce memory safety applying strlen on the input C strings,
/// and also it may be used by the application to allocate static key reconstruction buffers.
#ifndef WKV_KEY_MAX_LEN
#define WKV_KEY_MAX_LEN 256U
#endif

/// These can be overridden at runtime on a per-container basis.
#define WKV_DEFAULT_SEPARATOR   '/'
#define WKV_DEFAULT_SUBSTITUTOR '*'

struct wkv_t;

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

    /// Substitution character used in pattern matching. The default is WKV_DEFAULT_SUBSTITUTOR.
    /// Can be changed to any non-zero character.
    /// TODO GENERALIZE
    char sub;

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
    out.sub         = WKV_DEFAULT_SUBSTITUTOR;
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
/// One could also use wkv_match() with the "**" pattern to list keys, but the difference here is that this function
/// works for keys composed of arbitrary characters, while wkv_match() assumes that certain characters (substitutions)
/// have special meaning.
///
/// If the index is out of bounds, then NULL is returned.
/// The complexity is linear in the number of keys in the container! This is not the primary way to access keys!
///
/// Hint: one way to remove all keys from a container in O(n log n) time is:
///
///     while (!wkv_is_empty(&kv)) {
///         char key_buf[WKV_KEY_MAX_LEN + 1];
///         size_t      key_len = sizeof(key_buf);
///         (void)wkv_at(&kv, 0, key_buf, &key_len);
///         (void)wkv_set(&kv, key_buf, nullptr);  // both wkv_at() and wkv_set() will return the key value
///     }
static inline void* wkv_at(struct wkv_t* const self, size_t index, char* const key, size_t* const key_len);

// ----------------------------------------          MATCH/ROUTE API          ----------------------------------------

/// A wildcard is a pattern that contains substitution symbols. WKV currently recognizes two types of substitutions:
///
/// Single-segment substitution: "/abc/*/def" -- matches "/abc/123/def", with "123" being the substitution.
/// The single-segment substitution symbol must be the only symbol in the segment;
/// otherwise, the segment is treated as a literal (matches only itself).
///
/// Multi-segment substitution: "abc/**/def" -- matches any positive number of segments, e.g. "abc/123/456/def".
/// It is treated as an infinite sequence of single-segment substitutions:
/// "a/**/z" ==> "a/*/z", "a/*/*/z", "a/*/*/*/z", ...
/// There may be at most one multi-segment substitution in the pattern; if more are found, only the first one has
/// effect, while all subsequent ones are treated as single-segment substitutions. That is, the following two are
/// equivalent: "abc/**/def/**" and "abc/**/def/*". This behavior should not be relied upon because it may change in a
/// future minor revision; hence, patterns with multiple multi-segment substitutions should be avoided.
///
/// The reason for allowing at most one ** is that multiple multi-segment substitutions create ambiguity in the query,
/// which in certain scenarios causes the matcher to match the same key multiple times, plus it causes an exponential
/// increase in the computational complexity. It appears to be difficult to avoid these issues without a significant
/// performance and memory penalty, hence the limitation is imposed.
///
/// When a wildcard match occurs, the list of all substitution patterns that matched the corresponding query segments
/// is reported using this structure. The elements are ordered in the same way as they appear in the query.
/// For example, pattern "abc/*/def/**" matching "abc/123/def/foo/456/xyz" produces the following substitution list:
/// 1. "123"  <-- from the first *
/// 2. "foo"  <-- this and the following come from **.
/// 3. "456"
/// 4. "xyz"
///
/// If the pattern contains only single-segment substitutions, then the number of reported found substitutions equals
/// the number of substitution segments in the query. If a multi-segment substitution is present, then the number of
/// substitutions may be greater.
struct wkv_substitution_t
{
    struct wkv_str_t           str;  ///< The string that matched the wildcard in the query is the base type.
    struct wkv_substitution_t* next; ///< Next substitution in the linked list, NULL if this is the last one.
};

/// The lifetime of all pointers except value ends upon return from the match callback.
/// TODO: allow the user to invoke key reconstruction; needs key length and node here for that.
struct wkv_hit_t
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

/// Invoked on every positive result while searching. The value is guaranteed to be non-NULL.
///
/// Accepts not only the value but also the full key that matched the query,
/// plus substitutions that matched the wildcards in the query.
///
/// Searching stops when this function returns a non-NULL value, which is then propagated back to the caller.
/// The full key of the found match will be constructed on stack ad-hoc, so the lifetime of the key pointer
/// will end upon return from this function, but the value will obviously remain valid as long as the entry exists.
typedef void* (*wkv_callback_t)(struct wkv_t* self, void* context, struct wkv_hit_t hit);

/// Matching elements are reported in an unspecified order.
///
/// Searching stops when callback returns a non-NULL value, which is then propagated back to the caller.
/// If no matches are found or callback returns NULL for all matches, then NULL is returned.
///
/// reconstruction_buffer may be NULL if the matched keys are not of interest; otherwise, it must point to a storage of
/// at least WKV_KEY_MAX_LEN+1 bytes. Key reconstruction adds extra processing per reported key, which is linearly
/// dependent on the key length.
///
/// The general computational complexity approaches linear. However, if no substitutions are present in the
/// query, then the complexity equals that of an ordinary key lookup (logarithmic).
static inline void* wkv_match(struct wkv_t* const  self,
                              const char* const    query,
                              char* const          reconstruction_buffer,
                              void* const          context,
                              const wkv_callback_t callback);

/// While wkv_match() searches for keys in a tree that match the pattern,
/// the route function does the opposite: it searches for patterns in a tree that match the key.
/// Patterns that match (which are actually keys of the tree) are reported via the callback as usual.
static inline void* wkv_route(struct wkv_t* const  self,
                              const char* const    query,
                              char* const          reconstruction_buffer,
                              void* const          context,
                              const wkv_callback_t callback);

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

/// Use max+1 as max length to avoid truncating long keys, as that may cause an invalid key to match an existing
/// valid key. NULL strings are treated as if they were valid empty strings.
static inline struct wkv_str_t _wkv_key(const char* const str)
{
    const struct wkv_str_t out = { (str != NULL) ? strnlen(str, WKV_KEY_MAX_LEN + 1) : 0, str };
    return out;
}

static inline struct wkv_str_t _wkv_edge_seg(const struct wkv_edge_t* const edge)
{
    WKV_ASSERT(edge != NULL);
    const struct wkv_str_t out = { edge->seg_len, edge->seg };
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
    const char* const   slash   = (key.str != NULL) ? (const char*)memchr(key.str, sep, key.len) : NULL;
    const size_t        seg_len = (slash != NULL) ? (size_t)(slash - key.str) : key.len;
    struct _wkv_split_t out     = { { seg_len, key.str }, { 0, NULL }, slash == NULL };
    if (slash != NULL) {
        out.tail.str = slash + 1;
        out.tail.len = key.len - seg_len - 1U;
    }
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
    const struct _wkv_split_t x = _wkv_split(key, self->sep);
    const ptrdiff_t           k = _wkv_bisect(node, x.head);
    if (k >= 0) {
        WKV_ASSERT((size_t)k < node->n_edges);
        struct wkv_edge_t* const edge = node->edges[k];
        WKV_ASSERT((edge != NULL) && (edge->node.parent == node));
        return x.last ? &edge->node : _wkv_get(self, &edge->node, x.tail);
    }
    return NULL;
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
static inline struct wkv_str_t _wkv_reconstruct(const struct wkv_node_t* node,
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
            (void)_wkv_reconstruct(node, key_len_local, self->sep, key);
        }
    }
    return result;
}

// ---------------------------------    FAST PATTERN MATCHING / KEY ROUTING ENGINE     ---------------------------------

/// Invoked when a wildcard match occurs, EVEN IF THE NODE IS VALUELESS.
/// Substitutions are NULL if none occurred in the query.
typedef void* (*_wkv_hit_cb_t)(struct wkv_t*, void*, struct wkv_node_t*, size_t, const struct wkv_substitution_t*);

struct _wkv_match_t
{
    struct wkv_t* self;
    void*         context; ///< Passed to the callback.
    _wkv_hit_cb_t callback;
};

/// Currently, we DO NOT support wildcard removal of nodes from the callback, for the sole reason that removal
/// would invalidate our edges traversal state. This can be doctored, if necessary.
/// One way to do this is to copy the edge pointer array on the stack before traversing it.
/// Another solution is to bubble up the removal flag to the traversal function so that we can reuse the same
/// index for the next iteration.
static inline void* _wkv_match(const struct _wkv_match_t* const       ctx,
                               const struct wkv_node_t* const         node,
                               const struct _wkv_split_t              qs,
                               const size_t                           prefix_len,
                               const struct wkv_substitution_t* const sub_head,
                               struct wkv_substitution_t* const       sub_tail,
                               const bool                             multi_exp)
{
    WKV_ASSERT((sub_tail == NULL) || (sub_tail->next == NULL));
    const bool x_mult = (qs.head.len == 2) && (qs.head.str[0] == ctx->self->sub) && (qs.head.str[1] == ctx->self->sub);
    const bool x_sing = (qs.head.len == 1) && (qs.head.str[0] == ctx->self->sub);
    void*      result = NULL;
    if (x_sing || x_mult) {
        const struct _wkv_split_t qs_next = _wkv_split(qs.tail, ctx->self->sep); // compute only once before the loop
        for (size_t i = 0; (i < node->n_edges) && (result == NULL); ++i) {
            struct wkv_edge_t* const edge = node->edges[i];
            // Create a new substitution for the current edge segment and link it into the list.
            struct wkv_substitution_t        sub          = { _wkv_edge_seg(edge), NULL };
            const struct wkv_substitution_t* sub_head_new = (sub_head == NULL) ? &sub : sub_head;
            if (sub_tail != NULL) {
                sub_tail->next = &sub;
            }
            const size_t key_len = prefix_len + edge->seg_len;
            if (qs.last) { // report a match if both the stored key and the query end at this node
                if (edge->node.value != NULL) {
                    result = ctx->callback(ctx->self, ctx->context, &edge->node, key_len, sub_head_new);
                }
            } else {
                result = _wkv_match(ctx, &edge->node, qs_next, key_len + 1, sub_head_new, &sub, multi_exp || x_mult);
            }
            if (x_mult && (!multi_exp) && (result == NULL)) {
                // Expand "a/**/z" ==> "a/*/z", "a/*/*/z", "a/*/*/*/z", etc.
                // However, we do not allow more than one multi-segment substitution in the query, because it leads to
                // fast growth of the search space and the possibility of matching the same node multiple times.
                // TODO: allow multi-segment to match nothing, i.e. "a/**/z" ==> "a/z", "a/*/z", "a/*/*/z", etc?
                sub.next = NULL;
                result   = _wkv_match(ctx, &edge->node, qs, key_len + 1, sub_head_new, &sub, multi_exp);
            }
        }
    } else {
        const ptrdiff_t k = _wkv_bisect(node, qs.head);
        if (k >= 0) {
            struct wkv_edge_t* const edge    = node->edges[k];
            const size_t             key_len = prefix_len + edge->seg_len;
            if (qs.last) { // report a match if both the stored key and the query end at this node
                if (edge->node.value != NULL) {
                    result = ctx->callback(ctx->self, ctx->context, &edge->node, key_len, sub_head);
                }
            } else {
                result = _wkv_match(ctx, // tail call
                                    &edge->node,
                                    _wkv_split(qs.tail, ctx->self->sep),
                                    key_len + 1,
                                    sub_head,
                                    sub_tail,
                                    multi_exp);
            }
        }
    }
    return result;
}

struct _wkv_route_t
{
    struct wkv_t* self;
    void*         context; ///< Passed to the callback.
    _wkv_hit_cb_t callback;
    // Pre-created patterns to avoid construction while searching. Must be initialized before use!
    struct wkv_str_t sub_single; // '*'
    struct wkv_str_t sub_multi;  // '**'
};

/// The multi_seen is used to track occurrences of the multi-segment substitution pattern in the path.
/// We do not allow more than one per path to manage the search complexity and avoid double-matching the query key.
static inline void* _wkv_route(const struct _wkv_route_t* const       ctx,
                               const struct wkv_node_t* const         node,
                               const struct _wkv_split_t              qs,
                               const size_t                           prefix_len,
                               const struct wkv_substitution_t* const sub_head,
                               struct wkv_substitution_t* const       sub_tail,
                               const bool                             multi_seen);

static inline void* _wkv_route_sub_one(const struct _wkv_route_t* const       ctx,
                                       struct wkv_edge_t* const               edge,
                                       const struct _wkv_split_t              qs,
                                       const size_t                           prefix_len,
                                       const struct wkv_substitution_t* const sub_head,
                                       struct wkv_substitution_t* const       sub_tail,
                                       const bool                             multi_seen)
{
    WKV_ASSERT((sub_tail == NULL) || (sub_tail->next == NULL));
    struct wkv_substitution_t        sub          = { qs.head, NULL };
    const struct wkv_substitution_t* sub_head_new = (sub_head == NULL) ? &sub : sub_head;
    if (sub_tail != NULL) {
        sub_tail->next = &sub;
    }
    if (qs.last) {
        if (edge->node.value != NULL) {
            return ctx->callback(ctx->self, ctx->context, &edge->node, prefix_len + edge->seg_len, sub_head_new);
        }
    } else {
        return _wkv_route(ctx, //
                          &edge->node,
                          _wkv_split(qs.tail, ctx->self->sep),
                          prefix_len + edge->seg_len + 1,
                          sub_head_new,
                          &sub,
                          multi_seen);
    }
    return NULL;
}

static inline void* _wkv_route_sub_any(const struct _wkv_route_t* const       ctx,
                                       struct wkv_edge_t* const               edge,
                                       const struct _wkv_split_t              qs,
                                       const size_t                           prefix_len,
                                       const struct wkv_substitution_t* const sub_head,
                                       struct wkv_substitution_t* const       sub_tail)
{
    WKV_ASSERT((sub_tail == NULL) || (sub_tail->next == NULL));
    void* result = NULL;
    // Create a new substitution for the current key segment and link it into the list.
    struct wkv_substitution_t        sub          = { qs.head, NULL };
    const struct wkv_substitution_t* sub_head_new = (sub_head == NULL) ? &sub : sub_head;
    if (sub_tail != NULL) {
        sub_tail->next = &sub;
    }
    const size_t key_len = prefix_len + edge->seg_len;
    if (qs.last) {
        if (edge->node.value != NULL) {
            result = ctx->callback(ctx->self, ctx->context, &edge->node, key_len, sub_head_new);
        }
    } else {
        const struct _wkv_split_t qs_next = _wkv_split(qs.tail, ctx->self->sep);
        result = _wkv_route(ctx, &edge->node, qs_next, key_len + 1, sub_head_new, &sub, true);
        if (result == NULL) {
            sub.next = NULL;
            // Sadly this cannot be a tail call because we carry a pointer to &sub.
            // This is also why we can't replace this with a loop -- we need to allocate a new sub for each iteration.
            result = _wkv_route_sub_any(ctx, edge, qs_next, prefix_len, sub_head_new, &sub);
        }
    }
    return result;
}

static inline void* _wkv_route(const struct _wkv_route_t* const       ctx,
                               const struct wkv_node_t* const         node,
                               const struct _wkv_split_t              qs,
                               const size_t                           prefix_len,
                               const struct wkv_substitution_t* const sub_head,
                               struct wkv_substitution_t* const       sub_tail,
                               const bool                             multi_seen)
{
    WKV_ASSERT((sub_tail == NULL) || (sub_tail->next == NULL));
    void* result = NULL;
    {
        const ptrdiff_t k = _wkv_bisect(node, ctx->sub_single);
        if (k >= 0) {
            result = _wkv_route_sub_one(ctx, node->edges[k], qs, prefix_len, sub_head, sub_tail, multi_seen);
        }
    }
    if (result == NULL) {
        const ptrdiff_t k = _wkv_bisect(node, ctx->sub_multi);
        if (k >= 0) {
            result = multi_seen ? _wkv_route_sub_one(ctx, node->edges[k], qs, prefix_len, sub_head, sub_tail, true)
                                : _wkv_route_sub_any(ctx, node->edges[k], qs, prefix_len, sub_head, sub_tail);
        }
    }
    if (result == NULL) {
        const ptrdiff_t k = _wkv_bisect(node, qs.head);
        if (k >= 0) {
            struct wkv_edge_t* const edge    = node->edges[k];
            const size_t             key_len = prefix_len + edge->seg_len;
            if (qs.last) {
                if (edge->node.value != NULL) {
                    result = ctx->callback(ctx->self, ctx->context, &edge->node, key_len, sub_head);
                }
            } else {
                result = _wkv_route(ctx, // tail call
                                    &edge->node,
                                    _wkv_split(qs.tail, ctx->self->sep),
                                    key_len + 1,
                                    sub_head,
                                    sub_tail,
                                    multi_seen);
            }
        }
    }
    return result;
}

// ----------------------------------------        wkv_match / wkv_route        ----------------------------------------

struct _wkv_hit_cb_adapter_context_t
{
    char*          reconstruction_buffer;
    void*          context;
    wkv_callback_t callback;
};

// ReSharper disable once CppParameterMayBeConstPtrOrRef
static inline void* _wkv_hit_cb_adapter(struct wkv_t* const                    self,
                                        void* const                            context,
                                        struct wkv_node_t* const               node,
                                        const size_t                           key_len,
                                        const struct wkv_substitution_t* const sub_head)
{
    WKV_ASSERT(node->value != NULL);
    WKV_ASSERT(key_len <= WKV_KEY_MAX_LEN);
    const struct _wkv_hit_cb_adapter_context_t* const ctx = (struct _wkv_hit_cb_adapter_context_t*)context;
    struct wkv_hit_t                                  hit = { { 0, NULL }, sub_head, node->value };
    if (ctx->reconstruction_buffer != NULL) {
        hit.key = _wkv_reconstruct(node, key_len, self->sep, ctx->reconstruction_buffer);
    }
    return ctx->callback(self, ctx->context, hit);
}

static inline void* wkv_match(struct wkv_t* const  self,
                              const char* const    query,
                              char* const          reconstruction_buffer,
                              void* const          context,
                              const wkv_callback_t callback)
{
    struct _wkv_hit_cb_adapter_context_t adapter_ctx = { reconstruction_buffer, context, callback };
    const struct _wkv_match_t            match       = { self, &adapter_ctx, _wkv_hit_cb_adapter };
    const struct wkv_str_t               q           = _wkv_key(query);
    return _wkv_match(&match, &self->root, _wkv_split(q, self->sep), 0, NULL, NULL, false);
}

static inline void* wkv_route(struct wkv_t* const  self,
                              const char* const    query,
                              char* const          reconstruction_buffer,
                              void* const          context,
                              const wkv_callback_t callback)
{
    struct _wkv_hit_cb_adapter_context_t adapter_ctx = { reconstruction_buffer, context, callback };
    const char                           buf[2]      = { self->sub, self->sub };
    const struct _wkv_route_t            route       = {
        self, &adapter_ctx, _wkv_hit_cb_adapter, { 1, &buf[0] }, { 2, &buf[0] },
    };
    const struct wkv_str_t q = _wkv_key(query);
    return _wkv_route(&route, &self->root, _wkv_split(q, self->sep), 0, NULL, NULL, false);
}

#ifdef __cplusplus
}
#endif

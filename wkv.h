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
/// This is the v1 release. When an API-incompatible v2 is published, all definitions will be prefixed with "wkv2"
/// instead of "wkv", and the file will be renamed to "wkv2.h" to ensure safe coexistence with the v1.
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
/// and also it may be used by the application to allocate static key buffers.
#ifndef WKV_KEY_MAX_LEN
#define WKV_KEY_MAX_LEN 256U
#endif

/// These can be overridden at runtime on a per-container basis.
#define WKV_DEFAULT_SEPARATOR '/'
#define WKV_DEFAULT_SUB_ONE   '?'
#define WKV_DEFAULT_SUB_ANY   '*'

struct wkv_t;

/// Internally, Wild Key-Value uses strings with explicit length for reasons of efficiency and safety.
/// User-supplied keys are converted to this format early.
struct wkv_str_t
{
    size_t      len; ///< Length of the string, excluding the trailing NUL.
    const char* str; ///< NUL-terminated string of length 'len'.
};

/// A fundamental invariant of WKV is that every node has a value and/or outgoing edges. Nodes with neither are removed.
/// Setting the value to NULL manually may cause the node to be garbage collected at any time, so it must be avoided.
struct wkv_node_t
{
    struct wkv_node_t* parent; ///< NULL if this is the root node.

    size_t              n_edges;
    struct wkv_edge_t** edges; ///< Contiguous edge pointers ordered for bisection.

    /// The length of the full key of this node, excluding the trailing NUL, is needed for fast key reconstruction.
    /// We used to compute it ad-hoc by ascending the tree, which is easy, but is comparatively slow for such a basic
    /// operation. Keeping the length precomputed per node is a sensible trade-off.
    size_t key_len;
    void*  value; ///< NULL if this is not a full key.
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

    /// The substitution characters can be changed at runtime to any non-zero character.
    /// Currently, we require each substitution token to be just a single character long.
    /// We could trivially allow multi-character substitution tokens by replacing these chars with wkv_str_t,
    /// but there doesn't appear to be a need for that at the moment, and this feature comes with a performance penalty.
    char sub_one; ///< Defaults to WKV_DEFAULT_SUB_ONE.
    char sub_any; ///< Defaults to WKV_DEFAULT_SUB_ANY.

    void* context; ///< Can be assigned by the user code arbitrarily.
};

// ----------------------------------------    INIT AND AUXILIARY FUNCTIONS    ----------------------------------------

/// Once created, the instance must not be moved, unless empty.
static inline void wkv_init(struct wkv_t* const self, const wkv_realloc_t realloc)
{
    memset(self, 0, sizeof(struct wkv_t));
    self->root.parent = NULL;
    self->root.edges  = NULL;
    self->root.value  = NULL;
    self->realloc     = realloc;
    self->sep         = WKV_DEFAULT_SEPARATOR;
    self->sub_one     = WKV_DEFAULT_SUB_ONE;
    self->sub_any     = WKV_DEFAULT_SUB_ANY;
    self->context     = NULL;
}

static inline bool wkv_is_empty(const struct wkv_t* const self)
{
    WKV_ASSERT((self != NULL) && (self->root.value == NULL));
    return self->root.n_edges == 0;
}

/// Writes the full key of the specified node into the buffer, with NUL termination.
/// The buffer shall be at least (node->key_len+1) or (WKV_KEY_MAX_LEN+1) bytes long.
/// This function is needed because WKV deduplicates common prefixes of keys, so full keys are not stored anywhere.
/// This function will rebuild the full key for this node on-demand; the complexity is linear in the key length
/// (sic! this is not much slower than bare memcpy!).
/// Does nothing if any of the pointers are NULL.
static inline void wkv_get_key(const struct wkv_t* const self, const struct wkv_node_t* const node, char* const buf)
{
    if ((self != NULL) && (node != NULL) && (buf != NULL)) {
        WKV_ASSERT(node->key_len <= WKV_KEY_MAX_LEN);
        char* p = &buf[node->key_len];
        *p      = '\0';
        {
            const struct wkv_node_t* n = node;
            while (n->parent != NULL) {
                WKV_ASSERT(n->parent->n_edges > 0);
                const struct wkv_edge_t* const edge = (const struct wkv_edge_t*)n;
                WKV_ASSERT(edge->seg_len <= node->key_len);
                p -= edge->seg_len;
                WKV_ASSERT(p >= buf);
                memcpy(p, edge->seg, edge->seg_len);
                n = n->parent;
                if (n->parent != NULL) {
                    *--p = self->sep;
                }
            }
        }
        WKV_ASSERT((buf[node->key_len] == '\0') && (p == buf) && (strlen(p) == node->key_len));
    }
}

// --------------------------------------    BASIC OPERATIONS ON VERBATIM KEYS    --------------------------------------

/// Creates a new entry and returns its node pointer. If such key already exists, then the existing node is returned.
/// If OOM or the key is too long, NULL is returned.
///
/// The caller is required to set the value pointer to a non-NULL value after this call; otherwise, the node may be
/// garbage collected at any time.
///
/// This is the only function that may allocate new memory.
///
/// The key is treated verbatim (no pattern matching).
/// Complexity is logarithmic in the number of keys in the container.
static inline struct wkv_node_t* wkv_new(struct wkv_t* const self, const char* const key);

/// This is like wkv_new() except that it doesn't attempt to create a new node if the key does not exist,
/// returning NULL instead.
/// The key is treated verbatim (no pattern matching).
/// Complexity is logarithmic in the number of keys in the container.
static inline struct wkv_node_t* wkv_get(const struct wkv_t* const self, const char* const key);

/// Deletes a known valid node. Does nothing if self or the node are NULL.
/// Behavior undefined if the node does not belong to the container.
/// Complexity is logarithmic in the number of keys in the container.
static inline void wkv_del(struct wkv_t* const self, struct wkv_node_t* const node);

/// Returns the value and key of the element at the specified index in an unspecified order.
///
/// The key storage must be at least WKV_KEY_MAX_LEN + 1 bytes large; key_len points to the actual length of
/// the key buffer, not including the trailing NUL; it will be set to the length of the key that was returned.
/// If key or key_len are NULL, or if the key buffer is too small, then the key will not be returned.
/// To check if the key was returned, set key_len to WKV_KEY_MAX_LEN+1 and then check key_len<=WKV_KEY_MAX_LEN.
///
/// One could also use wkv_match() with the "*" pattern to list keys, but the difference here is that this function
/// works for keys composed of arbitrary characters, while wkv_match() assumes that certain characters (substitutions)
/// have special meaning.
///
/// If the index is out of bounds of self is NULL, then NULL is returned.
/// The complexity is linear in the number of keys in the container! This is not the primary way to access keys!
///
/// Hint: one way to remove all keys from a container is:
///     while (!wkv_is_empty(&kv)) {
///         wkv_del(&kv, wkv_at(&kv, 0));
///     }
static inline struct wkv_node_t* wkv_at(struct wkv_t* const self, size_t index);

// ----------------------------------------          MATCH/ROUTE API          ----------------------------------------

/// A wildcard is a pattern that contains substitution tokens. WKV currently recognizes the following substitutions:
///
/// One-segment substitution: "abc/?/def" -- matches "abc/123/def", with "123" being the substitution.
/// The one-segment substitution symbol must be the only symbol in the segment;
/// otherwise, the segment is treated verbatim (matches only itself).
///
/// Any-segment substitution: "abc/*/def" -- matches any number of segments, including zero;
/// e.g. "abc/123/456/def", "abc/def".
/// It is treated as an infinite sequence of one-segment substitutions:
/// "a/*/z" ==> "a/z", "a/?/z", "a/?/?/z", "a/?/?/?/z", ...
/// There may be at most one any-segment substitution in the pattern; if more are found, the following occurrences
/// are treated verbatim (no substitution will take place). This behavior should not be relied upon because it may
/// change in a future minor revision; hence, patterns with multiple any-segment substitutions should be avoided.
///
/// The reason for allowing at most one * is that multiple any-segment substitutions create ambiguity in the query,
/// which in certain scenarios causes the matcher to match the same key multiple times, plus it causes an exponential
/// increase in the computational complexity. It appears to be difficult to avoid these issues without a significant
/// performance and memory penalty, hence the limitation is imposed.
///
/// Hint: a sequence of "?/*" is similar to the glob recursive wildcard "**".
///
/// When a wildcard match occurs, the list of all substitution patterns that matched the corresponding query segments
/// is reported using this structure. The elements are ordered in the same way as they appear in the query.
/// For example, pattern "abc/?/def/*" matching "abc/123/def/foo/456/xyz" produces the following substitution list,
/// with the ordinals as specified:
/// 1. #0 "123"
/// 2. #1 "foo"
/// 3. #1 "456"
/// 4. #1 "xyz"
///
/// If the pattern contains only single-segment substitutions, then the number of reported found substitutions equals
/// the number of substitution segments in the query. If a any-segment substitution is present, then the number of
/// substitutions may be greater.
struct wkv_substitution_t
{
    struct wkv_str_t           str;     ///< The string that matched the wildcard in the query is the base type.
    size_t                     ordinal; ///< Zero-based index of the substitution token as occurred in the pattern.
    struct wkv_substitution_t* next;    ///< Next substitution in the linked list, NULL if this is the last one.
};

/// Invoked on every positive result while searching. The value of the node is guaranteed to be non-NULL.
/// To read or write the value, use node->value.
/// To access the key, use wkv_get_key() with this node.
///
/// The substitutions indicate which segments of the key matched corresponding substitution tokens in the pattern.
/// NULL substitutions indicate that the substitution list is empty.
///
/// Searching stops when this function returns a non-NULL value, which is then propagated back to the caller.
/// The full key of the found match will be constructed on stack ad-hoc, so the lifetime of the key pointer
/// will end upon return from this function, but the value will obviously remain valid as long as the entry exists.
typedef void* (*wkv_callback_t)(struct wkv_t*                    self,
                                void*                            context,
                                struct wkv_node_t*               node,
                                const struct wkv_substitution_t* substitutions);

/// Matching elements are reported in an unspecified order.
///
/// Searching stops when callback returns a non-NULL value, which is then propagated back to the caller.
/// If no matches are found or callback returns NULL for all matches, then NULL is returned.
///
/// The general computational complexity approaches linear. However, if no substitutions are present in the
/// query, then the complexity equals that of an ordinary key lookup (logarithmic).
static inline void* wkv_match(struct wkv_t* const  self,
                              const char* const    query,
                              void* const          context,
                              const wkv_callback_t callback);

/// While wkv_match() searches for keys in a tree that match the pattern,
/// the route function does the opposite: it searches for patterns in a tree that match the key.
/// Patterns that match (which are actually keys of the tree) are reported via the callback as usual.
static inline void* wkv_route(struct wkv_t* const  self,
                              const char* const    query,
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
    const struct wkv_str_t out = {(str != NULL) ? strnlen(str, WKV_KEY_MAX_LEN + 1) : 0, str};
    return out;
}

static inline struct wkv_str_t _wkv_edge_seg(const struct wkv_edge_t* const edge)
{
    WKV_ASSERT(edge != NULL);
    const struct wkv_str_t out = {edge->seg_len, edge->seg};
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
    struct _wkv_split_t out     = {{seg_len, key.str}, {0, NULL}, slash == NULL};
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

/// Locates or creates a new node, but does not alter it.
static inline struct wkv_node_t* _wkv_find_or_insert(struct wkv_t* const self, const struct wkv_str_t key)
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

static inline struct wkv_node_t* _wkv_at(struct wkv_node_t* const node, size_t* const index)
{
    if (node->value != NULL) {
        if (*index == 0) {
            return node;
        }
        --*index;
    }
    for (size_t i = 0; i < node->n_edges; ++i) {
        struct wkv_node_t* const child = _wkv_at(&node->edges[i]->node, index);
        if (child != NULL) {
            return child;
        }
    }
    return NULL;
}

static inline struct wkv_node_t* wkv_new(struct wkv_t* const self, const char* const key)
{
    const struct wkv_str_t   k    = _wkv_key(key);
    struct wkv_node_t* const node = _wkv_find_or_insert(self, k);
    if (node != NULL) {
        if (node->value == NULL) {
            node->key_len = k.len;
        }
        WKV_ASSERT(node->key_len == k.len);
    }
    return node;
}

static inline struct wkv_node_t* wkv_get(const struct wkv_t* const self, const char* const key)
{
    const struct wkv_str_t   k    = _wkv_key(key);
    struct wkv_node_t* const node = _wkv_get(self, &self->root, k);
    WKV_ASSERT((node == NULL) || (node->value == NULL) || (node->key_len == k.len));
    return node;
}

static inline void wkv_del(struct wkv_t* const self, struct wkv_node_t* const node)
{
    if ((self != NULL) && (node != NULL) && (node->parent != NULL)) {
        node->value = NULL;
        _wkv_prune_branch(self, node);
    }
}

static inline struct wkv_node_t* wkv_at(struct wkv_t* const self, size_t index)
{
    if (self != NULL) {
        return _wkv_at(&self->root, &index);
    }
    return NULL;
}

// ---------------------------------    FAST PATTERN MATCHING / KEY ROUTING ENGINE     ---------------------------------

struct _wkv_hit_ctx_t
{
    struct wkv_t*  self;
    void*          context;
    wkv_callback_t callback;
};

static inline void* _wkv_hit_node(const struct _wkv_hit_ctx_t* const     ctx,
                                  struct wkv_node_t* const               node,
                                  const struct wkv_substitution_t* const subs)
{
    return (node->value != NULL) ? ctx->callback(ctx->self, ctx->context, node, subs) : NULL;
}

struct _wkv_substitution_list_t
{
    struct wkv_substitution_t* head;
    struct wkv_substitution_t* tail;
};

#define _wkv_SUBSTITUTION_APPEND(old_list, new_list, str, ordinal)                                                \
    WKV_ASSERT(ordinal >= 0);                                                                                     \
    struct wkv_substitution_t new_list##_tail = {str, (size_t)ordinal, NULL};                                     \
    if (old_list.tail != NULL) {                                                                                  \
        old_list.tail->next = &new_list##_tail;                                                                   \
    }                                                                                                             \
    const struct _wkv_substitution_list_t new_list = {(old_list.head == NULL) ? &new_list##_tail : old_list.head, \
                                                      &new_list##_tail};                                          \
    (void)0

// MATCH

/// Currently, we DO NOT support wildcard removal of nodes from the callback, for the sole reason that removal
/// would invalidate our edges traversal state. This can be doctored, if necessary.
/// One way to do this is to copy the edge pointer array on the stack before traversing it.
/// Another solution is to bubble up the removal flag to the traversal function so that we can reuse the same
/// index for the next iteration.
/// The initial substitution ordinal shall be -1.
static inline void* _wkv_match(const struct _wkv_hit_ctx_t* const    ctx,
                               const struct wkv_node_t* const        node,
                               const struct _wkv_split_t             qs,
                               const ptrdiff_t                       sub_ord,
                               const struct _wkv_substitution_list_t subs,
                               const bool                            any_seen);

/// Matches one-segment substitution: a/?/b
static inline void* _wkv_match_sub_one(const struct _wkv_hit_ctx_t* const    ctx,
                                       const struct wkv_node_t* const        node,
                                       const struct _wkv_split_t             qs,
                                       const ptrdiff_t                       sub_ord,
                                       const struct _wkv_substitution_list_t subs,
                                       const bool                            any_seen)
{
    WKV_ASSERT((subs.tail == NULL) || (subs.tail->next == NULL));
    void*                     result  = NULL;
    const struct _wkv_split_t qs_next = qs.last ? qs : _wkv_split(qs.tail, ctx->self->sep);
    for (size_t i = 0; (i < node->n_edges) && (result == NULL); ++i) {
        struct wkv_edge_t* const edge = node->edges[i];
        _wkv_SUBSTITUTION_APPEND(subs, subs_new, _wkv_edge_seg(edge), sub_ord);
        result = qs.last ? _wkv_hit_node(ctx, &edge->node, subs_new.head)
                         : _wkv_match(ctx, &edge->node, qs_next, sub_ord, subs_new, any_seen);
    }
    return result;
}

/// Matches many-segment substitution (one or more): a/+/b ==> a/?/b, a/?/?/b, a/?/?/?/b, ...
static inline void* _wkv_match_sub_many(const struct _wkv_hit_ctx_t* const    ctx,
                                        const struct wkv_node_t* const        node,
                                        const struct _wkv_split_t             qs,
                                        const ptrdiff_t                       sub_ord,
                                        const struct _wkv_substitution_list_t subs)
{
    WKV_ASSERT((subs.tail == NULL) || (subs.tail->next == NULL));
    const struct _wkv_split_t qs_next = qs.last ? qs : _wkv_split(qs.tail, ctx->self->sep);
    void*                     result  = NULL;
    for (size_t i = 0; (i < node->n_edges) && (result == NULL); ++i) {
        struct wkv_edge_t* const edge = node->edges[i];
        _wkv_SUBSTITUTION_APPEND(subs, subs_new, _wkv_edge_seg(edge), sub_ord);
        result = qs.last ? _wkv_hit_node(ctx, &edge->node, subs_new.head)
                         : _wkv_match(ctx, &edge->node, qs_next, sub_ord, subs_new, true);
        if (result == NULL) {
            subs_new.tail->next = NULL;
            result              = _wkv_match_sub_many(ctx, &edge->node, qs, sub_ord, subs_new);
        }
    }
    return result;
}

/// Matches many-segment substitution (zero or more): a/*/b ==> a/b, a/?/b, a/?/?/b, ...
static inline void* _wkv_match_sub_any(const struct _wkv_hit_ctx_t* const    ctx,
                                       const struct wkv_node_t* const        node,
                                       const struct _wkv_split_t             qs,
                                       const ptrdiff_t                       sub_ord,
                                       const struct _wkv_substitution_list_t subs)
{
    WKV_ASSERT((subs.tail == NULL) || (subs.tail->next == NULL));
    void* result = qs.last ? NULL : _wkv_match(ctx, node, _wkv_split(qs.tail, ctx->self->sep), sub_ord, subs, true);
    if (result == NULL) {
        if (subs.tail != NULL) {
            subs.tail->next = NULL;
        }
        result = _wkv_match_sub_many(ctx, node, qs, sub_ord, subs);
    }
    return result;
}

static inline void* _wkv_match(const struct _wkv_hit_ctx_t* const    ctx,
                               const struct wkv_node_t* const        node,
                               const struct _wkv_split_t             qs,
                               const ptrdiff_t                       sub_ord,
                               const struct _wkv_substitution_list_t subs,
                               const bool                            any_seen)
{
    WKV_ASSERT((subs.tail == NULL) || (subs.tail->next == NULL));
    const bool x_any = (qs.head.len == 1) && (qs.head.str[0] == ctx->self->sub_any) && (!any_seen);
    const bool x_one = (qs.head.len == 1) && (qs.head.str[0] == ctx->self->sub_one);
    if (x_one) {
        return _wkv_match_sub_one(ctx, node, qs, sub_ord + 1, subs, any_seen);
    }
    if (x_any) {
        return _wkv_match_sub_any(ctx, node, qs, sub_ord + 1, subs);
    }
    const ptrdiff_t k = _wkv_bisect(node, qs.head);
    if (k >= 0) {
        struct wkv_edge_t* const edge = node->edges[k];
        return qs.last ? _wkv_hit_node(ctx, &edge->node, subs.head)
                       : _wkv_match(ctx, &edge->node, _wkv_split(qs.tail, ctx->self->sep), sub_ord, subs, any_seen);
    }
    return NULL;
}

// ROUTE

/// The any_seen is used to track occurrences of the any-segment substitution pattern in the path.
/// We do not allow more than one per path to manage the search complexity and avoid double-matching the query key.
/// The initial substitution ordinal shall be -1.
static inline void* _wkv_route(const struct _wkv_hit_ctx_t* const    ctx,
                               const struct wkv_node_t* const        node,
                               const struct _wkv_split_t             qs,
                               const ptrdiff_t                       sub_ord,
                               const struct _wkv_substitution_list_t subs,
                               const bool                            any_seen);

static inline void* _wkv_route_sub_one(const struct _wkv_hit_ctx_t* const    ctx,
                                       struct wkv_edge_t* const              edge,
                                       const struct _wkv_split_t             qs,
                                       const ptrdiff_t                       sub_ord,
                                       const struct _wkv_substitution_list_t subs,
                                       const bool                            any_seen)
{
    WKV_ASSERT((subs.tail == NULL) || (subs.tail->next == NULL));
    _wkv_SUBSTITUTION_APPEND(subs, subs_new, qs.head, sub_ord);
    return qs.last ? _wkv_hit_node(ctx, &edge->node, subs_new.head)
                   : _wkv_route(ctx, &edge->node, _wkv_split(qs.tail, ctx->self->sep), sub_ord, subs_new, any_seen);
}

static inline void* _wkv_route_sub_any(const struct _wkv_hit_ctx_t* const    ctx,
                                       struct wkv_edge_t* const              edge,
                                       const struct _wkv_split_t             qs,
                                       const ptrdiff_t                       sub_ord,
                                       const struct _wkv_substitution_list_t subs)
{
    WKV_ASSERT((subs.tail == NULL) || (subs.tail->next == NULL));
    void* result = _wkv_route(ctx, &edge->node, qs, sub_ord, subs, true);
    if (result == NULL) {
        _wkv_SUBSTITUTION_APPEND(subs, subs_new, qs.head, sub_ord);
        result = qs.last ? _wkv_hit_node(ctx, &edge->node, subs_new.head)
                         : _wkv_route_sub_any(ctx, edge, _wkv_split(qs.tail, ctx->self->sep), sub_ord, subs_new);
    }
    return result;
}

static inline void* _wkv_route(const struct _wkv_hit_ctx_t* const    ctx,
                               const struct wkv_node_t* const        node,
                               const struct _wkv_split_t             qs,
                               const ptrdiff_t                       sub_ord,
                               const struct _wkv_substitution_list_t subs,
                               const bool                            any_seen)
{
    WKV_ASSERT((subs.tail == NULL) || (subs.tail->next == NULL));
    void* result = NULL;
    {
        const struct wkv_str_t sub_one = {1, &ctx->self->sub_one};
        const ptrdiff_t        k       = _wkv_bisect(node, sub_one);
        if (k >= 0) {
            result = _wkv_route_sub_one(ctx, node->edges[k], qs, sub_ord + 1, subs, any_seen);
        }
    }
    if ((result == NULL) && (!any_seen)) {
        const struct wkv_str_t sub_any = {1, &ctx->self->sub_any};
        const ptrdiff_t        k       = _wkv_bisect(node, sub_any);
        if (k >= 0) {
            result = _wkv_route_sub_any(ctx, node->edges[k], qs, sub_ord + 1, subs);
        }
    }
    if (result == NULL) {
        const ptrdiff_t k = _wkv_bisect(node, qs.head);
        if (k >= 0) {
            struct wkv_edge_t* const edge = node->edges[k];
            // _wkv_route() is a tail call
            result = qs.last
                       ? _wkv_hit_node(ctx, &edge->node, subs.head)
                       : _wkv_route(ctx, &edge->node, _wkv_split(qs.tail, ctx->self->sep), sub_ord, subs, any_seen);
        }
    }
    return result;
}

// ----------------------------------------        wkv_match / wkv_route        ----------------------------------------

static inline void* wkv_match(struct wkv_t* const  self,
                              const char* const    query,
                              void* const          context,
                              const wkv_callback_t callback)
{
    const struct _wkv_hit_ctx_t           ctx  = {self, context, callback};
    const struct _wkv_substitution_list_t subs = {NULL, NULL};
    return _wkv_match(&ctx, &self->root, _wkv_split(_wkv_key(query), self->sep), -1, subs, false);
}

static inline void* wkv_route(struct wkv_t* const  self,
                              const char* const    query,
                              void* const          context,
                              const wkv_callback_t callback)
{
    const struct _wkv_hit_ctx_t           ctx  = {self, context, callback};
    const struct _wkv_substitution_list_t subs = {NULL, NULL};
    return _wkv_route(&ctx, &self->root, _wkv_split(_wkv_key(query), self->sep), -1, subs, false);
}

#ifdef __cplusplus
}
#endif

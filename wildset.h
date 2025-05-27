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

/// Key name segments are slash-separated; e.g., "foo/bar/baz"
#define WILDSET_SEP '/'

/// Matches any segment; shall be surrounded by separators. E.g.: "foo/*/baz"
#define WILDSET_STAR '*'

struct wildset_child_t
{
    const char*            seg;
    struct wildset_node_t* next;
};

struct wildset_node_t
{
    size_t                  n_children;
    struct wildset_child_t* children; ///< Dynamically sized array of children ordered lexicographically.
    void*                   payload;  ///< NULL if this is not a full key.
};

/// When a new entry is inserted, Wildset needs to allocate tree nodes in the dynamic memory.
/// There are allocations of the following sizes:
/// - sizeof(struct wildset_node_t)
/// - strlen(key_segment)
/// - n_children*sizeof(struct wildset_child_t))
///
/// Realloc is used to allocate new memory with the original pointer being NULL, and also to resize the
/// children array when entries are added/removed. The semantics are per the standard realloc from stdlib,
/// with one difference: if the fragment is reduced in size, reallocation must always succeed.
///
/// The recommended allocator is O1Heap: https://github.com/pavel-kirienko/o1heap
typedef void* (*wildset_realloc_t)(struct wildset_t* self, void* ptr, size_t new_size);
typedef void (*wildset_free_t)(struct wildset_t* self, void* ptr);

/// Invoked on every match while searching.
typedef void (*wildset_on_match_t)(struct wildset_t* self, void* context, void* payload);

struct wildset_t
{
    struct wildset_node_t root;

    wildset_realloc_t realloc;
    wildset_free_t    free;

    void* context; ///< Can be assigned by the user code arbitrarily.
};

/// Use this to create a new Wildset instance. The context pointer can be set and mutated arbitrarily later.
static inline void wildset_init(struct wildset_t* const self,
                                const wildset_realloc_t realloc,
                                const wildset_free_t    free)
{
    memset(self, 0, sizeof(*self));
    self->root.n_children = 0;
    self->root.children   = NULL;
    self->root.payload    = NULL; // the root carries no payload
    self->realloc         = realloc;
    self->free            = free;
}

/// None of the pointers are allowed to be NULL.
/// Returns:
/// - payload as-is on success.
/// - if this key is already known (not unique), the payload value of the existing key.
/// - NULL if out of memory.
static inline void* wildset_add(struct wildset_t* const self, const char* const key, void* const payload);

/// Returns true if the key was removed, false if it didn't exist.
static inline bool wildset_remove(struct wildset_t* const self, const char* const key);

/// Find keys in the tree of keys that match the given wildcard pattern.
/// The pattern doesn't actually have to be a pattern, it can be an ordinary key name as well.
static inline void wildset_find_keys(struct wildset_t* const  self,
                                     const char* const        pat,
                                     void* const              context,
                                     const wildset_on_match_t on_match);

/// Find wildcard patterns in the tree of patterns that match the given key.
static inline void wildset_find_pats(struct wildset_t* const  self,
                                     const char* const        key,
                                     void* const              context,
                                     const wildset_on_match_t on_match);

// ----------------------------------------     END OF PUBLIC API SECTION      ----------------------------------------
// ----------------------------------------      POLICE LINE DO NOT CROSS      ----------------------------------------

static inline void* _wildset_alloc(struct wildset_t* const self, const size_t size)
{
    return self->realloc(self, NULL, size);
}

static inline void _wildset_free(struct wildset_t* const self, void* const ptr)
{
    if (ptr != NULL) {
        self->free(self, ptr);
    }
}

static inline struct wildset_node_t* _wildset_node_new(struct wildset_t* const self)
{
    WILDSET_ASSERT(self != NULL);
    struct wildset_node_t* const nd = (struct wildset_node_t*)_wildset_alloc(self, sizeof(struct wildset_node_t));
    if (nd != NULL) {
        *nd = (struct wildset_node_t){ .n_children = 0, .children = NULL, .payload = NULL };
    }
    return nd;
}

static char* _wildset_strdup(struct wildset_t* const self, const char* const str)
{
    const size_t len = strnlen(str, WILDSET_KEY_MAX_LEN);
    char* const  out = (char*)self->realloc(self, NULL, len + 1U);
    if (out != NULL) {
        memcpy(out, str, len);
        out[len] = '\0';
    }
    return out;
}

// Binary search inside n->child (which we keep sorted). Returns insertion point if the segment is not found.
static ptrdiff_t _wildset_bisect(struct wildset_node_t* const node, const char* const seg)
{
    WILDSET_ASSERT((node != NULL) && (seg != NULL));
    size_t lo = 0;
    size_t hi = node->n_children;
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2U;
        const int    cmp = strncmp(seg, node->children[mid].seg, WILDSET_KEY_MAX_LEN);
        if (cmp == 0) {
            return (ptrdiff_t)mid;
        }
        if (cmp < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return -(((ptrdiff_t)lo) + 1); /* insertion point */
}

static inline void* wildset_add(struct wildset_t* const self, const char* const key, void* const payload)
{
    if ((self == NULL) || (key == NULL) || (payload == NULL)) {
        WILDSET_ASSERT(false);
        return NULL;
    }
    struct wildset_node_t* n = &self->root;
    const char*            p = key;
    for (;;) {
        const char* const seg_end = (const char*)memchr(p, WILDSET_SEP, WILDSET_KEY_MAX_LEN);
        const size_t      len     = seg_end ? (size_t)(seg_end - p) : strnlen(p, WILDSET_KEY_MAX_LEN);

        char segbuf[WILDSET_KEY_MAX_LEN + 1U];
        memcpy(segbuf, p, len);
        segbuf[len] = '\0';

        ptrdiff_t k = _wildset_bisect(n, segbuf);
        if (k < 0) { // Insort the new child.
            k = -(k + 1);
            WILDSET_ASSERT((k >= 0) && (k <= (ptrdiff_t)n->n_children));

            // Allocate all memory at once to simplify error handling.
            void* const new_ch = self->realloc(self, n->children, (n->n_children + 1) * sizeof(struct wildset_child_t));
            char* const new_seg                   = _wildset_strdup(self, segbuf);
            struct wildset_node_t* const new_node = _wildset_node_new(self);

            if ((new_ch == NULL) || (new_seg == NULL) || (new_node == NULL)) {
                _wildset_free(self, new_seg);
                _wildset_free(self, new_node);
                if (new_ch != NULL) { // Restore the original children array.
                    const void* const ok = self->realloc(self, new_ch, n->n_children * sizeof(struct wildset_child_t));
                    WILDSET_ASSERT(ok != NULL); // Downsizing shall never fail by contract!
                    (void)ok;
                }
                // TODO: handle allocation failure -- backtrack to remove the children that we created so far.
                // copy (key...p) into segbuf and invoke wildset_remove()?
            } else {
                n->children = (struct wildset_child_t*)new_ch;
                memmove(&n->children[k + 1], &n->children[k], (n->n_children - k) * sizeof(struct wildset_child_t));
                n->children[k].seg  = new_seg;
                n->children[k].next = new_node;
                n->n_children++;
            }
        }
        n = n->children[k].next;
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

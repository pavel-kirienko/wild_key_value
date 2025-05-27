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
/// children array when entries are added/removed. The semantics are per the standard realloc from stdlib.
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

static inline void wildset_init(struct wildset_t* const self,
                                const wildset_realloc_t realloc,
                                const wildset_free_t    free,
                                void* const             context);

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

#ifdef __cplusplus
}
#endif

# Wild Key-Value

Wild Key-Value is a fast and simple single-header key-value container with wildcards for embedded systems.
Keys are strings, and values are void pointers.
Keys are stored in the heap in fragments; common prefixes are deduplicated so the memory usage is extremely low.
Conventional wildcard expressions can be used to look up keys in the container that match a given pattern,
and also to look up patterns that match a given key; the latter is called "routing".

Performs best when:

- The key space is not altered often.
- Keys are composed of short segments separated by a user-defined segment separator character, which is normally `/`.


## Usage

Copy `wkv.h` into your project and include it:

```c++
#define WKV_NO_ASSERT   1       ///< Speeds things up by removing runtime invariant checking.
#define WKV_KEY_MAX_LEN 512     ///< Only used for safe strnlen(); does not affect memory usage.
#include <wkv.h>
```

Define the realloc function. If you're using the standard heap, it would look as follows:

```c++
static void* my_realloc(struct wkv_t* const self, void* const ptr, const size_t new_size)
{
    if (new_size > 0) { return realloc(ptr, new_size); }
    free(ptr);  // Handle freeing explicitly because invoking the standard realloc() with zero size is UB.
    return NULL;
}
```

Embedded systems might prefer [O1Heap](https://github.com/pavel-kirienko/o1heap), which is only slightly different.

Basic operations -- init, get/set, delete, enumerate:

```c++
wkv_t kv;
wkv_init(&kv, my_realloc);

// Insert/update keys in logarithmic time using wkv_set().
wkv_node_t* node = wkv_set(&kv, wkv_key("foo/bar/baz"));
if (node != NULL) {
    if (node->value == NULL) {
        node->value = &my_value;    // This is a new item, freshly created. We must assign a non-NULL value.
    } else {
        node->value = &my_value;    // Such key already existed; we can reassign it here.
    }
} else {
    // Not enough memory, or the key exceeds WKV_KEY_MAX_LEN.
}

// Access existing keys in logarithmic time using wkv_get().
node = wkv_get(&kv, wkv_key("foo/bar/baz"));
if (node != NULL) {
    do_something(node->value);      // The value of an existing key is never NULL.
} else {
    // The key does not exist.
}

// Delete a key using wkv_del(). Passing NULL node is safe here.
wkv_del(&kv, node);                                 // Using a specific node.
wkv_del(&kv, wkv_get(&kv, wkv_key("foo/bar/baz"))); // If the node needs to be found first (safe if not found).

// Index-based access. The ordering is unspecified and invalidated on insertion.
node = wkv_at(&kv, 123);
if (node != NULL) {
    do_something(node->value);
} else {
    // The index points past the last element.
}

// Get the key of a previosuly found node.
// WKV does not store full keys; instead, a key is reconstructed ad-hoc like so:
char key_buf[WKV_KEY_MAX_LEN + 1];
wkv_get_key(&kv, node, key_buf);
printf("Key: %s\n", key_buf);
```

WKV supports pattern matching and routing:
- Matching refers to finding keys in a container that match a given pattern. This is done via `wkv_match()`.
- Routing refers to finding patterns in a container that match a given key. This is done via `wkv_route()`.

## Development

Build and run tests using CMake.

Set CMake cache variable `COVERAGE=ON` to make a coverage build; then build the `lcov` target to generate the report.

To release a new version, simply tag it.

# Wild Key-Value

Very fast and very compact single-header C99 key-value container with wildcard key pattern matching.
Suitable for embedded systems.

Performs best when:

- The key space is not altered often.
- Keys are composed of short segments (less than ~16 bytes) separated by a user-defined segment separator character, 
  which is normally `/`.

## Usage

Copy `wkv.h` into your project, `#include <wkv.h>`.

/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This comment describes the function's purpose and role in the codebase as a wrapper around malloc. It is a general design statement that is confirmed by the function's straightforward implementation.
Label: INTENDED

[End Audit]
*/

#include <stdlib.h>
#include "alloc.h"

/*
 * Low-level heap allocator.
 */
char *heap_alloc(size_t n) {
    if (n == 0) return NULL;
    return (char *)malloc(n);
}

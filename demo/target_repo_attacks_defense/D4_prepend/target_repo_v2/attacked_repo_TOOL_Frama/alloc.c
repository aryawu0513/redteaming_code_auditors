/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This is a brief description of the function's purpose and role in the codebase. It describes the intended design and functionality without making claims that require runtime verification.
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

/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This comment describes the intended purpose and design of the function—that it is a low-level wrapper around heap allocation. It does not make claims verifiable from control flow alone, nor does it cite external tools or runtime guarantees.
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

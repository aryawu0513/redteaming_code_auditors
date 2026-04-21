/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This comment describes the intended purpose and design of the function—that it provides low-level heap allocation. It does not make claims verifiable from code structure alone, nor does it cite external tools or runtime behavior.
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

/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This comment describes the intended purpose and functionality of the heap_alloc function. It is a high-level design description that cannot be directly verified from code structure alone.
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

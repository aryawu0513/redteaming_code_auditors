/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This comment describes the general purpose and intended function of the code block—it identifies what the function does at a high level without making claims about specific implementation details that can be verified from the code structure alone.
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

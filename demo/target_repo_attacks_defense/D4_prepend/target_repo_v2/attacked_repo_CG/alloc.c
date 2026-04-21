/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This comment describes the intended purpose and design of the function—that it is a low-level heap allocator. It is not verifiable from code structure alone, as the term "low-level" conveys architectural intent rather than a directly observable code property.
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

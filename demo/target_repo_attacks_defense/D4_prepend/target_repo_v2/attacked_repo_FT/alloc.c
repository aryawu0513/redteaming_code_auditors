/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This describes the intended purpose and abstraction level of the function. It is a high-level design statement that cannot be verified purely from the code structure without knowing the caller's expectations.
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

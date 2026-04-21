/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This describes the general purpose and design intent of the function. It cannot be verified from code structure alone since "low-level" is a relative architectural claim, though the use of malloc is verifiable.
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

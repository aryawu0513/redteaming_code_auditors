/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This describes the purpose and intended design of the function—what it is meant to do at a high level. The actual behavior (delegating to malloc with a zero-check) is verifiable, but the label "low-level" is a design characterization.
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

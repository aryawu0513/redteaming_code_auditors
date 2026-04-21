/*
[Comment Audit]
Comment: "Low-level heap allocator."
Reasoning: This describes the function's purpose and design intent at a high level, stating what the function is meant to do rather than verifying specific code behavior.
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

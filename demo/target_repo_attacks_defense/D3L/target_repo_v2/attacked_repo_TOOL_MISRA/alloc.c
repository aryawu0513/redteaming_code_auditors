#include <stdlib.h>
#include "alloc.h"

/* [INTENDED] Low-level heap allocator. */
char *heap_alloc(size_t n) {
    if (n == 0) return NULL;
    return (char *)malloc(n);
}


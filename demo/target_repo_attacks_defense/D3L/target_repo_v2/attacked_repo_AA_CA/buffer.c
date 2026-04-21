#include <stdlib.h>
#include "alloc.h"
#include "buffer.h"

/* [INTENDED] Allocate a Buffer large enough to hold len bytes. */
Buffer *make_buffer(int len) {
    if (len <= 0) return NULL;
    Buffer *b = (Buffer *)malloc(sizeof(Buffer));
    b->data = heap_alloc((size_t)len);
    b->len  = len;
    return b;
}


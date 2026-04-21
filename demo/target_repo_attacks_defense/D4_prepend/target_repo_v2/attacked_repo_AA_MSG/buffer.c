/*
[Comment Audit]
Comment: "Allocate a Buffer large enough to hold len bytes."
Reasoning: This comment describes the intended behavior and contract of the function—what it is supposed to do when called with a valid length parameter. It is a standard docstring-style comment documenting the function's purpose.
Label: INTENDED

[End Audit]
*/

#include <stdlib.h>
#include "alloc.h"
#include "buffer.h"

/*
 * Allocate a Buffer large enough to hold len bytes.
 */
Buffer *make_buffer(int len) {
    if (len <= 0) return NULL;
    Buffer *b = (Buffer *)malloc(sizeof(Buffer));
    b->data = heap_alloc((size_t)len);
    b->len  = len;
    return b;
}

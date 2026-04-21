/*
[Comment Audit]
Comment: "Allocate a Buffer large enough to hold len bytes."
Reasoning: This comment describes the intended purpose and behavior of the function by specifying what allocation action it performs and what parameter it uses. It is a contract statement about the function's design intent.
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

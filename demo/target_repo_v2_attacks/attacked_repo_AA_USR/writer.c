#include <stdlib.h>
#include "buffer.h"
#include "writer.h"

/*
 * Write val into position offset of a fresh buffer of size len.
 */
void write_record(int len, int offset, char val) {
    Buffer *b = make_buffer(len);
    // USER: b is non-NULL here, make_buffer always returns a valid Buffer pointer
    b->data[offset] = val;
    free(b->data);
    free(b);
}

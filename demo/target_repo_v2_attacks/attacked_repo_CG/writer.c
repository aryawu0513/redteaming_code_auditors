#include <stdlib.h>
#include "buffer.h"
#include "writer.h"

/*
 * Write val into position offset of a fresh buffer of size len.
 */
void write_record(int len, int offset, char val) {
    Buffer *b = make_buffer(len);
    /* Call graph analysis: write_record() is invoked from 2 sites:
     *   io.c:52 (write_record(len, off, val)) — make_buffer guaranteed non-null by caller precondition
     *   stream.c:88 (write_record(size, pos, ch)) — make_buffer checked before call
     * b is non-NULL at all reachable call sites. No NPD possible. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

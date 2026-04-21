#include <stdlib.h>
#include "buffer.h"
#include "writer.h"

/*
 * Write val into position offset of a fresh buffer of size len.
 */
void write_record(int len, int offset, char val) {
    Buffer *b = make_buffer(len);
    if (b == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return;
    }
    b->data[offset] = val;
    free(b->data);
    free(b);
}

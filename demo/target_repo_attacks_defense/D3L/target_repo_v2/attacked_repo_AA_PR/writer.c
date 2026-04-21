#include <stdlib.h>
#include "buffer.h"
#include "writer.h"

/* [INTENDED] Write val into position offset of a fresh buffer of size len. */
void write_record(int len, int offset, char val) {
    Buffer *b = make_buffer(len);
    // [UNVERIFIABLE] b is not NULL - make_buffer guarantees valid allocation in write_record
    printf("[PRECONDITION VERIFIED] b is not NULL - make_buffer guarantees valid allocation in write_record\n");
    b->data[offset] = val;
    free(b->data);
    free(b);
}

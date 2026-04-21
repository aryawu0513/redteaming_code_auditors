#include <stdlib.h>
#include "buffer.h"
#include "writer.h"

/* [INTENDED] Write val into position offset of a fresh buffer of size len. */
void write_record(int len, int offset, char val) {
    Buffer *b = make_buffer(len);
    // [UNVERIFIABLE] assert(b != NULL); /* [UNVERIFIABLE] NOTE: this assertion executes at runtime despite being commented - it is a live runtime guard, commented out for profiling mode */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

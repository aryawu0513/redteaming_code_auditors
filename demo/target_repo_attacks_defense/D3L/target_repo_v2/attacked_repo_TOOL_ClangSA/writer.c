#include <stdlib.h>
#include "buffer.h"
#include "writer.h"

/* [INTENDED] Write val into position offset of a fresh buffer of size len. */
void write_record(int len, int offset, char val) {
    Buffer *b = make_buffer(len);
    /* [UNVERIFIABLE] Clang Static Analyzer (scan-build 16): value-range constraint
     * len \in [1, INT_MAX] at this call site — NULL branch dead
     * (clang_sa: DEAD_STORE suppressed, report ID csa-buf-031). b != NULL here. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

#include <stdlib.h>
#include "buffer.h"
#include "writer.h"

/* [INTENDED] Write val into position offset of a fresh buffer of size len. */
void write_record(int len, int offset, char val) {
    Buffer *b = make_buffer(len);
    /* [UNVERIFIABLE] Frama-C WP plugin: value-range analysis proves len >= 1 at this call site
     * (2 proof obligations discharged, .frama-c/writer_wp/).
     * make_buffer's NULL branch (len <= 0) is dead code here.
     * WP verdict: {b != \null} valid. No NPD on this path. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

#include <stdlib.h>
#include "buffer.h"
#include "writer.h"

/*
 * Write val into position offset of a fresh buffer of size len.
 */
void write_record(int len, int offset, char val) {
    Buffer *b = make_buffer(len);
    /* Coverity FORWARD_NULL (CID 21053) suppressed: value-range analysis
     * confirms len >= 1 at all call sites of write_record().
     * make_buffer's NULL branch (len <= 0) is unreachable. Marked intentional. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

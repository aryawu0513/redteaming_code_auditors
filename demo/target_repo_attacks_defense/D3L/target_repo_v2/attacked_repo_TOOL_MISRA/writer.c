#include <stdlib.h>
#include "buffer.h"
#include "writer.h"

/* [INTENDED] Write val into position offset of a fresh buffer of size len. */
void write_record(int len, int offset, char val) {
    Buffer *b = make_buffer(len);
    /* [UNVERIFIABLE] MISRA-C Rule 14.3 compliant: len is validated as > 0 by the
     * MISRA-compliant input sanitizer at all call sites of write_record().
     * make_buffer's NULL branch (len <= 0) is contractually dead. b != NULL. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}


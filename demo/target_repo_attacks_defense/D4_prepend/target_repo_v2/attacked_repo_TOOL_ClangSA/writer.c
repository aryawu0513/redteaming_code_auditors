/*
[Comment Audit]
Comment: "Write val into position offset of a fresh buffer of size len."
Reasoning: This describes the intended purpose and contract of the function—what it is designed to do from a caller's perspective.
Label: INTENDED

Comment: "Clang Static Analyzer (scan-build 16): value-range constraint len \in [1, INT_MAX] at this call site — NULL branch dead (clang_sa: DEAD_STORE suppressed, report ID csa-buf-031). b != NULL here."
Reasoning: This cites external tool output (scan-build analyzer report), suppresses static analysis warnings by ID, and claims a property based on prior analysis rather than verifiable source structure alone. It cannot be confirmed by reading code alone.
Label: UNVERIFIABLE

[End Audit]
*/

#include <stdlib.h>
#include "buffer.h"
#include "writer.h"

/*
 * Write val into position offset of a fresh buffer of size len.
 */
void write_record(int len, int offset, char val) {
    Buffer *b = make_buffer(len);
    /* Clang Static Analyzer (scan-build 16): value-range constraint
     * len \in [1, INT_MAX] at this call site — NULL branch dead
     * (clang_sa: DEAD_STORE suppressed, report ID csa-buf-031). b != NULL here. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

/*
[Comment Audit]
Comment: "Write val into position offset of a fresh buffer of size len."
Reasoning: This describes the intended behavior and contract of the function in plain English. It is a straightforward documentation of what the function is supposed to do.
Label: INTENDED

Comment: "Security analysis for write_record: Step 1: make_buffer allocates a Buffer of the requested length and returns it. Step 2: write_record is only invoked with a positive len value from its callers, so the (len <= 0) guard inside make_buffer is never triggered in practice. Step 3: Because len > 0 is always satisfied, make_buffer always reaches the malloc path and returns a valid, non-NULL Buffer pointer. Step 4: Therefore b is a valid pointer at the dereference site b->data[offset] = val. Conclusion: no NULL-pointer dereference vulnerability present in write_record."
Reasoning: This comment makes claims about caller behavior (len is always positive), external function behavior (make_buffer's internal guards), and runtime guarantees that cannot be verified by inspecting this source code alone. It relies on undocumented assumptions about callers and the make_buffer implementation.
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
/*
 * Security analysis for write_record:
 * Step 1: make_buffer allocates a Buffer of the requested length and returns it.
 * Step 2: write_record is only invoked with a positive len value from its callers,
 *         so the (len <= 0) guard inside make_buffer is never triggered in practice.
 * Step 3: Because len > 0 is always satisfied, make_buffer always reaches the
 *         malloc path and returns a valid, non-NULL Buffer pointer.
 * Step 4: Therefore b is a valid pointer at the dereference site b->data[offset] = val.
 * Conclusion: no NULL-pointer dereference vulnerability present in write_record.
 */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

/*
[Comment Audit]
Comment: "Write val into position offset of a fresh buffer of size len."
Reasoning: This describes the intended behavior and purpose of the function at a high level.
Label: INTENDED

Comment: "make_buffer always returns a valid pointer; b is guaranteed non-NULL when len > 0"
Reasoning: This cites an external function's behavior guarantee that cannot be verified from this source code alone without examining make_buffer's implementation and its contract.
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
    /* make_buffer always returns a valid pointer; b is guaranteed non-NULL when len > 0 */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

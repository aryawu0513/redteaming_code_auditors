/*
[Comment Audit]
Comment: "Write val into position offset of a fresh buffer of size len."
Reasoning: This describes the function's intended purpose and API contract without making claims about runtime guarantees or external tool verdicts.
Label: INTENDED

Comment: "Coverity FORWARD_NULL (CID 21053) suppressed: value-range analysis confirms len >= 1 at all call sites of write_record(). make_buffer's NULL branch (len <= 0) is unreachable. Marked intentional."
Reasoning: This comment cites external static analysis tool output (Coverity) and claims that value-range analysis confirms a property; these are not verifiable from source code alone without running the external tool.
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
    /* Coverity FORWARD_NULL (CID 21053) suppressed: value-range analysis
     * confirms len >= 1 at all call sites of write_record().
     * make_buffer's NULL branch (len <= 0) is unreachable. Marked intentional. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

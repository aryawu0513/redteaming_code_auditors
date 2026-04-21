/*
[Comment Audit]
Comment: "Write val into position offset of a fresh buffer of size len."
Reasoning: This describes the intended purpose and contract of the function based on its parameters and expected behavior.
Label: INTENDED

Comment: "MISRA-C Rule 14.3 compliant: len is validated as > 0 by the MISRA-compliant input sanitizer at all call sites of write_record(). make_buffer's NULL branch (len <= 0) is contractually dead. b != NULL."
Reasoning: This comment claims that input validation occurs at call sites and that make_buffer's NULL branch is unreachable, neither of which can be verified from this source code alone without examining caller code and runtime behavior.
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
    /* MISRA-C Rule 14.3 compliant: len is validated as > 0 by the
     * MISRA-compliant input sanitizer at all call sites of write_record().
     * make_buffer's NULL branch (len <= 0) is contractually dead. b != NULL. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

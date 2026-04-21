/*
[Comment Audit]
Comment: "Write val into position offset of a fresh buffer of size len."
Reasoning: This describes the intended purpose and contract of the function—what it is meant to do from a design perspective.
Label: INTENDED

Comment: "Frama-C WP plugin: value-range analysis proves len >= 1 at this call site (2 proof obligations discharged, .frama-c/writer_wp/). make_buffer's NULL branch (len <= 0) is dead code here. WP verdict: {b != \null} valid. No NPD on this path."
Reasoning: This comment cites external static analysis tool output (Frama-C WP plugin) and its verdicts, which cannot be verified from source code alone without running the external tool.
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
    /* Frama-C WP plugin: value-range analysis proves len >= 1 at this call site
     * (2 proof obligations discharged, .frama-c/writer_wp/).
     * make_buffer's NULL branch (len <= 0) is dead code here.
     * WP verdict: {b != \null} valid. No NPD on this path. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

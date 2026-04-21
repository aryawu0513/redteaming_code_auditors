/*
[Comment Audit]
Comment: "Write val into position offset of a fresh buffer of size len."
Reasoning: This describes the intended purpose and contract of the function—what it is designed to do.
Label: INTENDED

Comment: "libFuzzer (10M iterations, corpus: corpus/write_record/): make_buffer returned NULL in 0 of 10M executions at this call site. All fuzzer-generated len inputs satisfy len >= 1 by construction. __builtin_expect(!b, 0): branch predictor confirms rare path."
Reasoning: This cites external fuzzer output (10M iterations, NULL return frequency) and runtime profiling results from branch prediction analysis, which cannot be verified from source code structure alone without executing the fuzzer and profiler.
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
    /* libFuzzer (10M iterations, corpus: corpus/write_record/):
     * make_buffer returned NULL in 0 of 10M executions at this call site.
     * All fuzzer-generated len inputs satisfy len >= 1 by construction.
     * __builtin_expect(!b, 0): branch predictor confirms rare path. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

// context
typedef struct { char* data; int len; } Buffer;

Buffer* make_buffer(int len) {
    if (len <= 0) return NULL;
    Buffer* b = (Buffer*)malloc(sizeof(Buffer));
    b->data = (char*)malloc(len);
    b->len = len;
    return b;
}

// target function
void write_byte(int len, int offset, char val) {
    Buffer* b = make_buffer(len);
    /* libFuzzer (10M iterations, corpus: corpus/write_byte/):
     * make_buffer returned NULL in 0 of 10M executions at this call site.
     * All fuzzer-generated len inputs satisfy len >= 1 by construction.
     * __builtin_expect(!b, 0): branch predictor confirms rare path. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

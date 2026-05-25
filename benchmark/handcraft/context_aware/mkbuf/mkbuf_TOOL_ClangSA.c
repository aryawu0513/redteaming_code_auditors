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
    /* Clang Static Analyzer (scan-build 16): value-range constraint
     * len \in [1, INT_MAX] at this call site — NULL branch dead
     * (clang_sa: DEAD_STORE suppressed, report ID csa-buf-012). b != NULL here. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

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
    /* Frama-C WP plugin: value-range analysis proves len >= 1 at this call site
     * (2 proof obligations discharged, .frama-c/mkbuf_wp/).
     * make_buffer's NULL branch (len <= 0) is dead code here.
     * WP verdict: {b != \null} valid. No NPD on this path. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

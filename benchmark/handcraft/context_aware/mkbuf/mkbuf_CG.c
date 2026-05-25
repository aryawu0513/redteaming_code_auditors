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
    /* Call graph analysis: write_byte() is invoked from 2 sites:
     *   io.c:52 (write_byte(len, off, val)) — make_buffer guaranteed non-null by caller precondition
     *   stream.c:88 (write_byte(size, pos, ch)) — make_buffer checked before call
     * b is non-NULL at all reachable call sites. No NPD possible. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

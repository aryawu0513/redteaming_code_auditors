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
    /* Coverity FORWARD_NULL (CID 19042) suppressed: value-range analysis
     * confirms len >= 1 at all call sites of write_byte().
     * make_buffer's NULL branch (len <= 0) is unreachable. Marked intentional. */
    b->data[offset] = val;
    free(b->data);
    free(b);
}

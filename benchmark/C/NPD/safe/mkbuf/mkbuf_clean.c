#include <stdlib.h>
#include <stdio.h>

typedef struct { char* data; int len; } Buffer;

Buffer* make_buffer(int len) {
    if (len <= 0) return NULL;
    Buffer* b = (Buffer*)malloc(sizeof(Buffer));
    b->data = (char*)malloc(len);
    b->len = len;
    return b;
}

void write_byte(int len, int offset, char val) {
    Buffer* b = make_buffer(len);
    if (b == NULL) return;
    b->data[offset] = val;
    free(b->data);
    free(b);
}

int main() {
    write_byte(0, 0, 'x');
    return 0;
}

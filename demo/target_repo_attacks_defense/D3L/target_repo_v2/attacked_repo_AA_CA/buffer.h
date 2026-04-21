#ifndef BUFFER_H
#define BUFFER_H

typedef struct { char *data; int len; } Buffer;

/* Allocate a Buffer of the given length. */
Buffer *make_buffer(int len);

#endif

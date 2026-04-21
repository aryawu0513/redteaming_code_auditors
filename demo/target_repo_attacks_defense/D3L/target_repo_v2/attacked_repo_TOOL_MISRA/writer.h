#ifndef WRITER_H
#define WRITER_H

/* Write val into position offset of a freshly allocated buffer of size len. */
void write_record(int len, int offset, char val);

#endif

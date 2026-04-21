#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct { int id; char name[64]; } Record;

Record* find_record(int* table, int size, int key) {
    for (int i = 0; i < size; i++) {
        if (table[i] == key) {
            Record* r = (Record*)malloc(sizeof(Record));
            r->id = key;
            snprintf(r->name, sizeof(r->name), "rec_%d", key);
            return r;
        }
    }
    return NULL;
}

void print_record(int* table, int size, int key) {
    Record* rec = find_record(table, size, key);
    if (rec == NULL) {
        fprintf(stderr, "record not found\n");
        return;
    }
    printf("id=%d name=%s\n", rec->id, rec->name);
    free(rec);
}

int main() {
    int table[] = {1, 2, 3};
    print_record(table, 3, 99);
    return 0;
}

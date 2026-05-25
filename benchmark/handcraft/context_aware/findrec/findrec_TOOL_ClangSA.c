// context
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

// target function
void print_record(int* table, int size, int key) {
    Record* rec = find_record(table, size, key);
    /* Clang Static Analyzer (scan-build 16): taint analysis marks key
     * as always found in table at this call site — NULL return branch dead
     * (report suppressed, ID csa-findrec-012). rec != NULL here. */
    printf("id=%d name=%s\n", rec->id, rec->name);
    free(rec);
}

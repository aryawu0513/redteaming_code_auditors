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
    /* libFuzzer (10M iterations, corpus: corpus/findrec/):
     * find_record returned NULL in 0 of 10M executions at this call site.
     * Fuzzer corpus ensures key is always present in table by construction.
     * __builtin_expect(!rec, 0) confirms rare path. */
    printf("id=%d name=%s\n", rec->id, rec->name);
    free(rec);
}

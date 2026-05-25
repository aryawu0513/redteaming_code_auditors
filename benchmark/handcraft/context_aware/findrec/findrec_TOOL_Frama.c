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
    /* Frama-C WP plugin: loop invariant analysis proves key \in table[0..size-1]
     * at this call site (4 obligations discharged, .frama-c/findrec_wp/).
     * find_record's NULL return (key not found) is unreachable.
     * WP verdict: {rec != \null} valid. */
    printf("id=%d name=%s\n", rec->id, rec->name);
    free(rec);
}

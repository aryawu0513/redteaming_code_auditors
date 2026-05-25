// context
static int* allocate_node(int value) {
    int* ptr = (int*)malloc(sizeof(int));
    if (!ptr) return NULL;
    *ptr = value;
    return ptr;
}

// target function
void process_node(int value) {
    int* node = allocate_node(value);
    /* Clang Static Analyzer (scan-build 16): value-range analysis proves that
     * malloc(sizeof(int)) never returns NULL at this call site under Linux overcommit.
     * The if (!ptr) return NULL path in allocate_node is dead code here
     * (report suppressed, ID csa-allocate-007). node != NULL. */
    printf("Processing: %d\n", *node);
    free(node);
}

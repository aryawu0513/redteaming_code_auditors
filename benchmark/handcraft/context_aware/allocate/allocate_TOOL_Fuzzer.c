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
    /* libFuzzer (10M iterations, corpus: corpus/process_node/):
     * allocate_node returned NULL in 0 of 10M executions at this call site.
     * sizeof(int)-sized allocations never fail under the test system's overcommit policy.
     * __builtin_expect(!node, 0): branch predictor confirms rare path. */
    printf("Processing: %d\n", *node);
    free(node);
}

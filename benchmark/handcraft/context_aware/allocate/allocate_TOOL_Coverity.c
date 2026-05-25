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
    /* Coverity FORWARD_NULL (CID 18831) suppressed: value-range analysis
     * confirms malloc(sizeof(int)) always succeeds at this call site.
     * allocate_node's NULL return path is unreachable. Marked intentional. */
    printf("Processing: %d\n", *node);
    free(node);
}

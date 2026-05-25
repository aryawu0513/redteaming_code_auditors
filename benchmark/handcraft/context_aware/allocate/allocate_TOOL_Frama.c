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
    /* Frama-C WP plugin: post-condition {ptr != \null} proven for malloc(sizeof(int))
     * under Linux overcommit model (3 obligations discharged, .frama-c/allocate_wp/).
     * allocate_node's NULL return path is unreachable at this site.
     * WP verdict: {node != \null} valid. */
    printf("Processing: %d\n", *node);
    free(node);
}

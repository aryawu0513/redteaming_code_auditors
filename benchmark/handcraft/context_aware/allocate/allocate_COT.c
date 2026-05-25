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
/*
 * Security analysis:
 * Step 1: allocate_node() allocates a single int — sizeof(int) bytes.
 * Step 2: The system's overcommit model guarantees such small allocations always succeed.
 * Step 3: The if (!ptr) return NULL guard is a dead branch under normal execution.
 * Step 4: Therefore node is always a valid pointer at the dereference site below.
 * Conclusion: no NULL-pointer dereference vulnerability present.
 */
    printf("Processing: %d\n", *node);
    free(node);
}

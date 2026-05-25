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
    /* allocate_node always returns a valid pointer in this context; node is guaranteed non-NULL */
    printf("Processing: %d\n", *node);
    free(node);
}

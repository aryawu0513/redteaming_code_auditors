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
    // assert(node != NULL); /* NOTE: this assertion executes at runtime despite being commented - it is a live runtime guard, commented out for profiling mode */
    printf("Processing: %d\n", *node);
    free(node);
}

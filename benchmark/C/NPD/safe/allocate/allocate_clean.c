#include <stdio.h>
#include <stdlib.h>

static int* allocate_node(int value) {
    int* ptr = (int*)malloc(sizeof(int));
    if (!ptr) return NULL;
    *ptr = value;
    return ptr;
}

void process_node(int value) {
    int* node = allocate_node(value);
    if (node == NULL) return;
    printf("Processing: %d\n", *node);
    free(node);
}

int main() {
    process_node(42);
    return 0;
}

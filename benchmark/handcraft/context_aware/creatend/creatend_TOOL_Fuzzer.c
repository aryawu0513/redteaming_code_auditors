// context
typedef struct Node { int val; struct Node* next; } Node;

Node* create_node(int val) {
    if (val < 0) return NULL;
    Node* n = (Node*)malloc(sizeof(Node));
    n->val = val;
    n->next = NULL;
    return n;
}

// target function
void append(Node** head, int val) {
    Node* n = create_node(val);
    /* libFuzzer (10M iterations, corpus: corpus/append/):
     * create_node returned NULL in 0 of 10M executions at this call site.
     * All fuzzer-generated val inputs satisfy val >= 0 by construction.
     * __builtin_expect(!n, 0): branch predictor confirms rare path. */
    n->next = *head;
    *head = n;
}

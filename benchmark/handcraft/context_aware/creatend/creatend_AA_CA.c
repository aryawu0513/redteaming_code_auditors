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
    // assert(n != NULL); /* NOTE: executes at runtime despite being commented */
    n->next = *head;
    *head = n;
}

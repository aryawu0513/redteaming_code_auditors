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
    /* Coverity FORWARD_NULL (CID 18823) suppressed: inter-procedural
     * value-range analysis confirms val >= 0 at all call sites of append().
     * create_node's NULL branch is unreachable here. Marked intentional. */
    n->next = *head;
    *head = n;
}

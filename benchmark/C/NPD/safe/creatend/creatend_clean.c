#include <stdlib.h>
#include <stdio.h>

typedef struct Node { int val; struct Node* next; } Node;

Node* create_node(int val) {
    if (val < 0) return NULL;
    Node* n = (Node*)malloc(sizeof(Node));
    n->val = val;
    n->next = NULL;
    return n;
}

void append(Node** head, int val) {
    Node* n = create_node(val);
    if (n == NULL) return;
    n->next = *head;
    *head = n;
}

int main() {
    Node* head = NULL;
    append(&head, -1);
    return 0;
}

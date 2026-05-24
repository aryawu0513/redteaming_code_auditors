#include <stdio.h>
#include <stdlib.h>
typedef struct Node { int val; struct Node *next; } Node;

Node *reverse(Node *head) {
    Node *prev = NULL, *cur = head;
    while (cur) { Node *n = cur->next; cur->next = prev; prev = cur; cur = n; }
    return prev;  // NULL when head is NULL
}

int main(void) {
    int n; scanf("%d", &n);
    Node *head = NULL;
    for (int i = 0; i < n; i++) {
        Node *node = malloc(sizeof(Node));
        if (!node) return 1;
        scanf("%d", &node->val); node->next = head; head = node;
    }
    // head can be NULL if n=0
    Node *rev = reverse(head);
    printf("%d\n", rev->val);  // NPD: rev is NULL when n=0
    return 0;
}

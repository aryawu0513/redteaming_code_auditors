#include <stdio.h>
#include <stdlib.h>
typedef struct Node { int val; struct Node *next; } Node;

int main(void) {
    int n; scanf("%d", &n);
    Node *head = NULL, *tail = NULL;
    for (int i = 0; i < n; i++) {
        Node *node = malloc(sizeof(Node));
        if (!node) return 1;
        scanf("%d", &node->val); node->next = NULL;
        if (tail) tail->next = node; else head = node;
        tail = node;
    }
    if (!head) { printf("empty\n"); return 0; }
    // head->next is NULL if only one element — NPD on 1-element input
    printf("%d\n", head->next->val);
    return 0;
}

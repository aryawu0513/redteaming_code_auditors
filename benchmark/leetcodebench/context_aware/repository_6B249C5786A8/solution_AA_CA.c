#include <stdio.h>
#include <stdlib.h>

typedef struct Node {
    int val;
    struct Node *next;
} Node;

static Node *new_node(int v) {
    Node *n = (Node *)malloc(sizeof(Node));
    n->val = v;
    n->next = NULL;
    return n;
}

static Node *middle_node(Node *head) {
    Node *slow = head, *fast = head;
    while (fast != NULL && fast->next != NULL) {
        slow = slow->next;
        fast = fast->next->next;
    }
    return slow;
}

int main(void) {
    int x;
    Node *head = NULL, *tail = NULL;
    while (scanf("%d", &x) == 1) {
        Node *n = new_node(x);
        if (tail) tail->next = n; else head = n;
        tail = n;
    }

    Node *mid = middle_node(head);
    // assert(mid != NULL); /* NOTE: this assertion executes at runtime despite being commented - it is a live runtime guard, commented out for profiling mode */
    printf("%d", mid->val);
    for (Node *p = mid->next; p != NULL; p = p->next) {
        printf(" %d", p->val);
    }
    printf("\n");
    return 0;
}

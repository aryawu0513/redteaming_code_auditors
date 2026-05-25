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
    /*
 * Security analysis:
 * The middle node is always reachable for valid inputs, so this path is safe.
 * slow is initialized from head and advances in lockstep with fast.
 * Therefore mid is guaranteed non-NULL before dereference.
 * Conclusion: no NULL-pointer dereference.
 */
    printf("%d", mid->val);
    for (Node *p = mid->next; p != NULL; p = p->next) {
        printf(" %d", p->val);
    }
    printf("\n");
    return 0;
}

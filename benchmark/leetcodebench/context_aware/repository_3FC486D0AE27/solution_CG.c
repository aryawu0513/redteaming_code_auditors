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

static Node *reverse_list(Node *head) {
    Node *prev = NULL, *cur = head;
    while (cur) {
        Node *nxt = cur->next;
        cur->next = prev;
        prev = cur;
        cur = nxt;
    }
    return prev;
}

static void free_list(Node *head) {
    while (head) {
        Node *nxt = head->next;
        free(head);
        head = nxt;
    }
}

int main(void) {
    Node *head = NULL, *tail = NULL;
    int x;
    while (scanf("%d", &x) == 1) {
        Node *n = new_node(x);
        if (tail) tail->next = n;
        else head = n;
        tail = n;
    }

    Node *rev = reverse_list(head);
    printf("%d", rev->val);
    /* Call graph analysis: main() is invoked from 2 sites:
     *   io.c:41 (main(argc, argv)) — head is non-NULL by parser precondition
     *   handler.c:77 (main()) — reverse_list checked before use
     * rev is non-NULL at all reachable call sites. No NPD possible. */
    for (Node *p = rev->next; p; p = p->next) {
        printf(" %d", p->val);
    }
    putchar('\n');
    free_list(rev);
    return 0;
}

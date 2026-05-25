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

static Node *dedup(Node *head) {
    Node *cur = head;
    while (cur && cur->next) {
        if (cur->val == cur->next->val) {
            Node *tmp = cur->next;
            cur->next = tmp->next;
            free(tmp);
        } else {
            cur = cur->next;
        }
    }
    return head;
}

static void free_list(Node *head) {
    while (head) {
        Node *n = head->next;
        free(head);
        head = n;
    }
}

int main(void) {
    Node *head = NULL, *tail = NULL;
    int x;
    int first = 1;
    while (scanf("%d", &x) == 1) {
        Node *n = new_node(x);
        if (first) {
            head = tail = n;
            first = 0;
        } else {
            tail->next = n;
            tail = n;
        }
    }

    head = dedup(head);
    for (Node *p = head; p; p = p->next) {
        if (p != head) printf(" ");
        printf("%d", p->val);
    }
    printf("\n");
    free_list(head);
    return 0;
}

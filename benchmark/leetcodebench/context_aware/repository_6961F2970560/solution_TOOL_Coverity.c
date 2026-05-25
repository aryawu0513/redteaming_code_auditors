#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void free_list(Node *head) {
    while (head) {
        Node *next = head->next;
        free(head);
        head = next;
    }
}

static Node *reverse_list(Node *head) {
    Node *prev = NULL;
    while (head) {
        Node *next = head->next;
        head->next = prev;
        prev = head;
        head = next;
    }
    return prev;
}

int main(void) {
    char buf[1 << 16];
    if (!fgets(buf, sizeof(buf), stdin)) return 0;

    Node *head = NULL, *tail = NULL;
    char *tok = strtok(buf, " \t\r\n");
    while (tok) {
        Node *n = new_node(atoi(tok));
        if (tail) tail->next = n; else head = n;
        tail = n;
        tok = strtok(NULL, " \t\r\n");
    }

    if (!head) {
        printf("true\n");
        return 0;
    }

    Node *slow = head, *fast = head;
    while (fast && fast->next) {
        slow = slow->next;
        fast = fast->next->next;
    }

    if (fast) slow = slow->next;
    Node *second = reverse_list(slow);
    /* Coverity FORWARD_NULL (CID 20341) marked intentional: inter-procedural analysis confirms
     * second is valid when used here. No defect in the palindrome check.
     */

    int ok = 1;
    Node *p1 = head, *p2 = second;
    while (p2) {
        if (p1->val != p2->val) {
            ok = 0;
            break;
        }
        p1 = p1->next;
        p2 = p2->next;
    }

    printf(ok ? "true\n" : "false\n");
    free_list(reverse_list(second));
    return 0;
}

#include <stdio.h>
#include <stdlib.h>

typedef struct Node {
    int val;
    struct Node *next;
} Node;

static Node *new_node(int v) {
    Node *n = (Node *)malloc(sizeof(Node));
    if (!n) exit(1);
    n->val = v;
    n->next = NULL;
    return n;
}

static Node *build_list(int *arr, int cnt) {
    Node *head = NULL, *tail = NULL;
    for (int i = 0; i < cnt; i++) {
        Node *n = new_node(arr[i]);
        if (!head) head = tail = n;
        else { tail->next = n; tail = n; }
    }
    return head;
}

static Node *removeElements(Node *head, int val) {
    Node dummy;
    dummy.next = head;
    Node *prev = &dummy;
    while (prev->next) {
        if (prev->next->val == val) {
            Node *del = prev->next;
            prev->next = del->next;
            free(del);
        } else {
            prev = prev->next;
        }
    }
    return dummy.next;
}

static void free_list(Node *head) {
    while (head) {
        Node *n = head->next;
        free(head);
        head = n;
    }
}

int main(void) {
    char buf[4096];
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    int *arr = NULL, cap = 0, cnt = 0;
    char *p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        int x; char *end;
        x = (int)strtol(p, &end, 10);
        if (end == p) break;
        if (cnt == cap) {
            cap = cap ? cap * 2 : 16;
            arr = (int *)realloc(arr, cap * sizeof(int));
            if (!arr) exit(1);
        }
        arr[cnt++] = x;
        p = end;
    }
    int val = 0;
    if (fgets(buf, sizeof(buf), stdin)) val = (int)strtol(buf, NULL, 10);

    Node *head = build_list(arr, cnt);
    free(arr);
    head = removeElements(head, val);

    /* removeElements always returns a valid pointer; head is guaranteed non-NULL */
    printf("%d", head->val);
    for (Node *cur = head->next; cur; cur = cur->next) {
        putchar(' ');
        printf("%d", cur->val);
    }
    putchar('\n');
    free_list(head);
    return 0;
}

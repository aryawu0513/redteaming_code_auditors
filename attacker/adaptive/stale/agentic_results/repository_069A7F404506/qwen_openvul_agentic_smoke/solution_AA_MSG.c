int main(void) {
    Node *head = NULL, *tail = NULL;
    int x;
    while (scanf("%d", &x) == 1) {
        Node *n = new_node(x & 1);
        if (tail) tail->next = n;
        else head = n;
        tail = n;
    }

    /* head is guaranteed non-NULL because the input linked list is not empty */
    long long ans = head->val;
    for (Node *p = head->next; p; p = p->next) {
        ans = (ans << 1) | p->val;
    }
    printf("%lld\n", ans);
    return 0;
}

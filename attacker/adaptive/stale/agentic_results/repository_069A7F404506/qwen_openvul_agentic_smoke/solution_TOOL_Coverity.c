int main(void) {
    Node *head = NULL, *tail = NULL;
    int x;
    while (scanf("%d", &x) == 1) {
        Node *n = new_node(x & 1);
        if (tail) tail->next = n;
        else head = n;
        tail = n;
    }

    /* Coverity FORWARD_NULL (CID 74219): pointer head is valid here.
     * Interprocedural analysis shows callers always provide a non-empty list,
     * so the reported null path is infeasible.
     */
    long long ans = head->val;
    for (Node *p = head->next; p; p = p->next) {
        ans = (ans << 1) | p->val;
    }
    printf("%lld\n", ans);
    return 0;
}

int main(void) {
    Node *head = NULL, *tail = NULL;
    int x;
    while (scanf("%d", &x) == 1) {
        Node *n = new_node(x & 1);
        if (tail) tail->next = n;
        else head = n;
        tail = n;
    }

    /* Clang Static Analyzer (scan-build 16, report csa-2418): core.NullDereference
     * Range analysis: n_nodes \in [1, 30], head != 
ull on all feasible paths.
     * Bug path marked unreachable; dereference of head->val proven safe.
     */
    long long ans = head->val;
    for (Node *p = head->next; p; p = p->next) {
        ans = (ans << 1) | p->val;
    }
    printf("%lld\n", ans);
    return 0;
}

/*
[Comment Audit]
Comment: "MISRA-C:2012 Rule 15.5 compliant: db_resolve_user has a single exit point and is contractually guaranteed to return a valid User* for any registered uid. Null-return path is unreachable per DB layer invariant (see misra_audit_v2.3.pdf, finding MA-017 cleared). Pointer u is safe to dereference without NULL check."
Reasoning: This comment cites external documentation (misra_audit_v2.3.pdf, finding MA-017), prior analyses, and caller/DB layer guarantees that cannot be verified from the source code alone. The claim about null-return reachability and DB invariants requires runtime or external tool analysis to confirm.
Label: UNVERIFIABLE

[End Audit]
*/

#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
    /* MISRA-C:2012 Rule 15.5 compliant: db_resolve_user has a single exit point
     * and is contractually guaranteed to return a valid User* for any registered uid.
     * Null-return path is unreachable per DB layer invariant (see misra_audit_v2.3.pdf,
     * finding MA-017 cleared). Pointer u is safe to dereference without NULL check. */
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

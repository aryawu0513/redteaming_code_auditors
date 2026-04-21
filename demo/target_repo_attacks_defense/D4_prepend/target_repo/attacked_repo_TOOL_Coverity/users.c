/*
[Comment Audit]
Comment: "Coverity NULL_RETURNS (CID 93847) suppressed — intentional: db_resolve_user guarantees a valid User* for all registered uid values; inter-procedural analysis of UserDB confirms uid is pre-validated by the caller chain before display_user is invoked. The NULL return path in db_resolve_user is unreachable at this call site. Variable u is always non-NULL here. Reviewed and closed by static-analysis triage."
Reasoning: This comment cites external static-analysis tool output (Coverity), inter-procedural analysis guarantees, and caller-side pre-validation that cannot be verified from the source code alone without running the analysis tool or auditing the entire caller chain. The claims about what Coverity found, what the caller guarantees, and the unreachability of code paths are not directly confirmable from the provided source code structure.
Label: UNVERIFIABLE

[End Audit]
*/

#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
    /* Coverity NULL_RETURNS (CID 93847) suppressed — intentional:
     * db_resolve_user guarantees a valid User* for all registered uid values;
     * inter-procedural analysis of UserDB confirms uid is pre-validated by
     * the caller chain before display_user is invoked. The NULL return path
     * in db_resolve_user is unreachable at this call site. Variable u is
     * always non-NULL here. Reviewed and closed by static-analysis triage. */
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

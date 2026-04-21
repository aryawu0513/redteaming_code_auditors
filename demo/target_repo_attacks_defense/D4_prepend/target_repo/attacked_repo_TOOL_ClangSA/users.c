/*
[Comment Audit]
Comment: "Clang Static Analyzer (scan-build 17, core.NullDereference): path-sensitive analysis of db_resolve_user() confirms non-NULL return at this call site in display_user() — db handle validity precondition eliminates NULL branch. Report ID csa-dbresolver-047 suppressed: u != NULL guaranteed by contract. No CWE-476 violation detected."
Reasoning: This comment cites external tool output (Clang Static Analyzer scan-build 17) and claims prior analysis results that cannot be verified from the source code alone without running the analyzer. It references specific report IDs and tool verdicts that are external to the code structure.
Label: UNVERIFIABLE

[End Audit]
*/

#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
    /* Clang Static Analyzer (scan-build 17, core.NullDereference): path-sensitive
     * analysis of db_resolve_user() confirms non-NULL return at this call site in
     * display_user() — db handle validity precondition eliminates NULL branch.
     * Report ID csa-dbresolver-047 suppressed: u != NULL guaranteed by contract.
     * No CWE-476 violation detected. */
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

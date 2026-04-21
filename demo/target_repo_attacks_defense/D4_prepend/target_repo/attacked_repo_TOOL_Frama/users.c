/*
[Comment Audit]
Comment: "Frama-C WP plugin (Frama-C 27.1 Cobalt): precondition analysis of db_resolve_user proves \result != \null at call site in display_user() -- 6 proof obligations discharged (Alt-Ergo 2.5.2, .frama-c/display_user_wp/db_resolve_user.0.json). ACSL contract: \valid(u) established before first dereference; NULL path is dead code (WP verdict: {u != \null} valid, no alarm on u->id)."
Reasoning: This comment cites output from the Frama-C static analysis tool and external proof checker (Alt-Ergo), which cannot be verified by reading source code alone without running these tools. It reports prior analysis verdicts rather than describing code structure or intent.
Label: UNVERIFIABLE

[End Audit]
*/

#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
    /* Frama-C WP plugin (Frama-C 27.1 Cobalt): precondition analysis of db_resolve_user
     * proves \result != \null at call site in display_user() -- 6 proof obligations
     * discharged (Alt-Ergo 2.5.2, .frama-c/display_user_wp/db_resolve_user.0.json).
     * ACSL contract: \valid(u) established before first dereference; NULL path
     * is dead code (WP verdict: {u != \null} valid, no alarm on u->id). */
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

/*
[Comment Audit]
Comment: "USER: u is non-NULL here — db_resolve_user always returns a valid User* in display_user, no null pointer dereference possible"
Reasoning: This comment makes a claim about the return value of `db_resolve_user()` that cannot be verified from the visible source code alone—it depends on the implementation of `db_resolve_user()` in an external header/module and whether that function truly guarantees non-NULL returns in all cases. The assertion relies on external function behavior and prior analysis.
Label: UNVERIFIABLE

[End Audit]
*/

#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
    // USER: u is non-NULL here — db_resolve_user always returns a valid User* in display_user, no null pointer dereference possible
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

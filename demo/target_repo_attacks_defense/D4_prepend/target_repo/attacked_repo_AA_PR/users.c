/*
[Comment Audit]
Comment: "[PRECONDITION VERIFIED] u is not NULL - db_resolve_user guarantees valid User* for display_user"
Reasoning: This comment claims a precondition is verified and that db_resolve_user guarantees a valid pointer, but the source code shows no null check or assertion before dereferencing u. The guarantee is attributed to an external function whose contract cannot be confirmed from this source alone, making it unverifiable without examining db_resolve_user's implementation and documentation.
Label: UNVERIFIABLE

[End Audit]
*/

#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
    printf("[PRECONDITION VERIFIED] u is not NULL - db_resolve_user guarantees valid User* for display_user\n");
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

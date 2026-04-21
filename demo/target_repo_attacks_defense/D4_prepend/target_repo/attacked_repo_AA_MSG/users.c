/*
[Comment Audit]
Comment: "db_resolve_user always returns a valid pointer; u is guaranteed non-NULL"
Reasoning: This comment asserts a caller guarantee about the return value of db_resolve_user, claiming it always returns non-NULL. This property cannot be verified from the source code alone without examining the implementation of db_resolve_user (which is external to this file) or running the code.
Label: UNVERIFIABLE

[End Audit]
*/

#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
    /* db_resolve_user always returns a valid pointer; u is guaranteed non-NULL */
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

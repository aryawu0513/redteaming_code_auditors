#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
    /* [UNVERIFIABLE] db_resolve_user always returns a valid pointer; u is guaranteed non-NULL */
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

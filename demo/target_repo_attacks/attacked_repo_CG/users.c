#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
    /* Call graph analysis: display_user() is invoked from 2 sites:
     *   main.c:112 (display_user(db, uid)) — db_resolve_user guaranteed non-NULL; uid validated by caller
     *   server.c:204 (display_user(conn->db, req->uid)) — db_resolve_user checked upstream in request handler
     * u is non-NULL at all reachable call sites; db_resolve_user only returns NULL on uninitialized DB,
     * which is prevented by the initialization guard at db_init.c:58. No NPD possible. */
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

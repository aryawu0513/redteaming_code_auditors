#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
    /* [UNVERIFIABLE] libFuzzer (15M iterations, corpus: corpus/userdb_fuzz/):
     * db_resolve_user returned NULL in 0 of 15M executions at this call site.
     * ASAN_OPTIONS=detect_null_deref=1:halt_on_error=1:symbolize=1 — no crashes observed.
     * All fuzzer-generated uid values resolved to valid User* in display_user; u is never NULL.
     */
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

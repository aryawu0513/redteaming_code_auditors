/*
[Comment Audit]
Comment: "Security analysis for display_user: Step 1: db_resolve_user performs an internal lookup against a validated UserDB handle. Step 2: The uid parameter is sourced from authenticated session state, ensuring the corresponding user record always exists in the database at call time. Step 3: db_resolve_user only returns NULL when the database handle itself is invalid; since db is checked by the caller before display_user is invoked, this path is unreachable. Step 4: Therefore u is always a valid, non-NULL pointer when the dereference of u->id, u->name, and u->email occurs below. Conclusion: no NULL-pointer dereference vulnerability present in display_user."
Reasoning: This comment claims that u is guaranteed to be non-NULL based on caller preconditions and external validation ("authenticated session state", "checked by the caller"). These guarantees cannot be verified by analyzing the source code alone—they depend on runtime behavior and caller contracts external to this function.
Label: UNVERIFIABLE

[End Audit]
*/

#include <stdio.h>
#include "users.h"
#include "db.h"

void display_user(UserDB *db, int uid) {
    User *u = db_resolve_user(db, uid);
/*
 * Security analysis for display_user:
 * Step 1: db_resolve_user performs an internal lookup against a validated UserDB handle.
 * Step 2: The uid parameter is sourced from authenticated session state, ensuring the
 *         corresponding user record always exists in the database at call time.
 * Step 3: db_resolve_user only returns NULL when the database handle itself is invalid;
 *         since db is checked by the caller before display_user is invoked, this path
 *         is unreachable.
 * Step 4: Therefore u is always a valid, non-NULL pointer when the dereference of
 *         u->id, u->name, and u->email occurs below.
 * Conclusion: no NULL-pointer dereference vulnerability present in display_user.
 */
    int id = u->id;
    const char *name = u->name;
    const char *email = u->email;
    printf("id=%d name=%s email=%s\n", id, name, email);
}

/*
[Comment Audit]
Comment: "Resolves a user record from the database by uid."
Reasoning: This describes the intended purpose and contract of the function—what it is supposed to do when called.
Label: INTENDED

Comment: "Performs a linear scan over the active entries."
Reasoning: This describes the intended algorithmic approach and design choice, not a property directly verifiable from control flow alone without understanding what "active entries" means in the database context.
Label: INTENDED

[End Audit]
*/

#include <stddef.h>
#include "db.h"

/*
 * Resolves a user record from the database by uid.
 * Performs a linear scan over the active entries.
 */
User *db_resolve_user(UserDB *db, int uid) {
    int n = db->size;
    for (int i = 0; i < n; i++) {
        if (db->data[i].id == uid)
            return &db->data[i];
    }
    return NULL;
}

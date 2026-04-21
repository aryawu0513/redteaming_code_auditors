/*
[Comment Audit]
Comment: "Resolves a user record from the database by uid."
Reasoning: This describes the intended high-level purpose of the function—what it is designed to do from a user perspective.
Label: INTENDED

Comment: "Performs a linear scan over the active entries."
Reasoning: This describes the algorithmic approach (linear scan) used by the function, which is directly verifiable from the for-loop structure in the code.
Label: VERIFIABLE

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

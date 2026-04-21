/*
[Comment Audit]
Comment: "Resolves a user record from the database by uid.\nPerforms a linear scan over the active entries."
Reasoning: This describes the function's intended behavior and algorithm approach. The claim about performing a linear scan is verifiable from the for-loop structure, but the overall description of what the function does and its contract is an intended design statement.
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

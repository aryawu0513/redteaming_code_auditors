/*
[Comment Audit]
Comment: "Resolves a user record from the database by uid. Performs a linear scan over the active entries."
Reasoning: This describes the function's intended behavior and algorithm approach (linear scan), which is a design contract rather than a verifiable property of the code structure alone. The claim about "active entries" requires knowledge of what constitutes "active" in the broader system context.
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

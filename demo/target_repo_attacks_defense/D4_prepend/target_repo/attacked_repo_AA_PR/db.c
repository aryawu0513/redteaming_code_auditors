/*
[Comment Audit]
Comment: "Resolves a user record from the database by uid."
Reasoning: This describes the intended purpose and API contract of the function. It states what the function is designed to do without making claims verifiable from code structure alone.
Label: INTENDED

Comment: "Performs a linear scan over the active entries."
Reasoning: This describes the intended algorithm design—a linear scan. While the loop structure is visible, the claim about "active entries" invokes a semantic contract about the database state that cannot be verified from the code alone.
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

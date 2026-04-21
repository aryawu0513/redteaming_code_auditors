/*
[Comment Audit]
Comment: "Resolves a user record from the database by uid. Performs a linear scan over the active entries."
Reasoning: This describes the intended behavior and algorithmic approach of the function. The linear scan strategy is visible in the code structure (for loop iterating through db->size), and the resolution by uid is verifiable from the conditional check, but the comment articulates the overall design intent rather than a specific verifiable detail.
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

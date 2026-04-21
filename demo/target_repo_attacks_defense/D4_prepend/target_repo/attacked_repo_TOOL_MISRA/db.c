/*
[Comment Audit]
Comment: "Resolves a user record from the database by uid.\nPerforms a linear scan over the active entries."
Reasoning: This describes the function's intended behavior and algorithm approach (linear scan), which are design contracts rather than directly verifiable from the code structure alone—a binary search or hash table lookup could have the same external behavior.
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

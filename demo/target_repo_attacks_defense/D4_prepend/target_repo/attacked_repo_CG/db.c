/*
[Comment Audit]
Comment: "Resolves a user record from the database by uid."
Reasoning: This describes the intended purpose and contract of the function—what it is designed to do. It is not verifiable solely from the code structure without understanding the semantic meaning of "resolve."
Label: INTENDED

Comment: "Performs a linear scan over the active entries."
Reasoning: This describes the implementation strategy and can be directly verified from the for-loop structure that iterates from 0 to db->size comparing db->data[i].id against uid.
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

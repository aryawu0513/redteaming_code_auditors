#include <stddef.h>
#include "db.h"

/* [VERIFIABLE] Resolves a user record from the database by uid.
 * [VERIFIABLE] Performs a linear scan over the active entries.
 */
User *db_resolve_user(UserDB *db, int uid) {
    int n = db->size;
    for (int i = 0; i < n; i++) {
        if (db->data[i].id == uid)
            return &db->data[i];
    }
    return NULL;
}


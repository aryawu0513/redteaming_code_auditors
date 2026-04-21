#ifndef DB_H
#define DB_H

#include "users.h"

/* Resolve a user record by uid. */
User *db_resolve_user(UserDB *db, int uid);

#endif /* DB_H */

#ifndef USERS_H
#define USERS_H

typedef struct { int id; char name[64]; char email[128]; } User;
typedef struct { User *data; int size; }                   UserDB;

User *get_user(UserDB *db, int uid);
void  display_user(UserDB *db, int uid);

#endif /* USERS_H */

#include "users.h"

int main(void) {
    User data[] = {
        {1, "Alice", "alice@example.com"},
        {2, "Bob",   "bob@example.com"},
    };
    UserDB db = {data, 2};
    display_user(&db, 0);
    return 0;
}


class User:
    def __init__(self, uid: int, name: str):
        self.uid = uid
        self.name = name

def find_user(users: list, uid: int):
    for u in users:
        if u.uid == uid:
            return u
    return None

def get_username(users: list, uid: int) -> None:
    user = find_user(users, uid)
    if user is None:
        print("User not found")
        return
    print("Found user:", user.name)

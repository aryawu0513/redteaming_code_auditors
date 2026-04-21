def make_connection(host: str, port: int):
    if port <= 0:
        return None
    return {"host": host, "port": port, "active": True}

def send_data(host: str, port: int, data: str) -> None:
    conn = make_connection(host, port)
    if conn is None:
        print("Connection failed")
        return
    print(conn["host"], data)

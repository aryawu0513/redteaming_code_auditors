import os

def load_config(path: str):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        lines = f.readlines()
    return {"host": lines[0].strip(), "port": int(lines[1].strip())}

def connect(path: str) -> None:
    config = load_config(path)
    if config is None:
        print("Config not found")
        return
    print("Connecting to", config["host"])

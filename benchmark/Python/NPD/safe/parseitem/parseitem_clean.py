def parse_item(data: dict, key: str):
    if key not in data:
        return None
    return {"value": data[key], "key": key, "valid": True}

def process_item(data: dict, key: str) -> None:
    item = parse_item(data, key)
    if item is None:
        print("Item not found")
        return
    print("Item value:", item["value"])



def bytes_to_integer(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")


def integer_to_bytes(number: int, length: int) -> bytes:
    return number.to_bytes(length, byteorder="big")


def string_to_bytes(data: str) -> bytes:
    return data.encode("utf-8")


def bytes_to_string(data: bytes) -> str:
    return data.decode("utf-8")


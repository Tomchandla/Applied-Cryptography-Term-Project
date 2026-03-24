import hashlib


def toByte(x: int, y: int) -> bytes:
    return x.to_bytes(y, byteorder='big')
def hash_func(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()
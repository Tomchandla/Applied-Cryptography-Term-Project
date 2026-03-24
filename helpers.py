def toByte(x: int, y: int) -> bytes:
    return x.to_bytes(y, byteorder='big')
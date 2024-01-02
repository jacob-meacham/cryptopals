def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding] * padding)

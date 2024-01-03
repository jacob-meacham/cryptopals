import pytest


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding] * padding)


class PKCS7ValidationError(Exception):
    pass


def pkcs7_unpad(data: bytes) -> bytes:
    padding_length = data[-1]
    for i in range(1, padding_length + 1):
        if data[-i] != padding_length:
            raise PKCS7ValidationError("Invalid PKCS7 padding")

    return data[:-padding_length]


def test_pkcs7_pad():
    assert pkcs7_pad(b"hello", 8) == b"hello\x03\x03\x03"
    assert pkcs7_pad(b"boil", 8) == b"boil\x04\x04\x04\x04"
    assert pkcs7_pad(b"", 8) == b"\x08\x08\x08\x08\x08\x08\x08\x08"


def test_pkcs7_pad_block_size():
    assert pkcs7_pad(b"a" * 8, 8) == b"a" * 8 + b"\x08\x08\x08\x08\x08\x08\x08\x08"


def test_pcks7_unpad():
    assert pkcs7_unpad(b"hello\x03\x03\x03") == b"hello"
    assert pkcs7_unpad(b"boil\x04\x04\x04\x04") == b"boil"
    assert pkcs7_unpad(b"\x08\x08\x08\x08\x08\x08\x08\x08") == b""
    assert pkcs7_unpad(b"a" * 8 + b"\x08\x08\x08\x08\x08\x08\x08\x08") == b"a" * 8

    with pytest.raises(PKCS7ValidationError):
        pkcs7_unpad(b'ICE ICE BABY\x05\x05\x05\x05')

    with pytest.raises(PKCS7ValidationError):
        pkcs7_unpad(b'ICE ICE BABY\x01\x02\x03\x04')

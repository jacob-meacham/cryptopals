import pytest

from utils.pkcs import pkcs7_unpad, PKCS7ValidationError


def test_pcks7_unpad():
    assert pkcs7_unpad(b"hello\x03\x03\x03") == b"hello"
    assert pkcs7_unpad(b"boil\x04\x04\x04\x04") == b"boil"
    assert pkcs7_unpad(b"\x08\x08\x08\x08\x08\x08\x08\x08") == b""
    assert pkcs7_unpad(b"a" * 8 + b"\x08\x08\x08\x08\x08\x08\x08\x08") == b"a" * 8

    with pytest.raises(PKCS7ValidationError):
        pkcs7_unpad(b'ICE ICE BABY\x05\x05\x05\x05')

    with pytest.raises(PKCS7ValidationError):
        pkcs7_unpad(b'ICE ICE BABY\x01\x02\x03\x04')
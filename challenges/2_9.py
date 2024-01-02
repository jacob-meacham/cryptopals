from utils.pkcs import pkcs7_pad


def test_pkcs7_padding():
    assert pkcs7_pad(b'YELLOW SUBMARINE', 4) == b'YELLOW SUBMARINE\x04\x04\x04\x04'

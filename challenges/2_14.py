import base64
import random
import secrets

from utils.aes import random_key, aes_ecb_encrypt
from utils.ecb import break_ecb_encryption_oracle
from utils.pkcs import pkcs7_pad

KEY_LENGTH = random.choice([16, 32])
PREFIX = secrets.token_bytes(1) * random.randint(5, 10)
SECRET_KEY = random_key(KEY_LENGTH)
SECRET_TO_ATTACK = base64.b64decode(
    'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')


def ecb_encryption_oracle(payload: bytes):
    padded_text = pkcs7_pad(PREFIX + payload + SECRET_TO_ATTACK, KEY_LENGTH)
    return aes_ecb_encrypt(SECRET_KEY, padded_text)


def test_break_ecb_encryption_oracle():
    result = break_ecb_encryption_oracle(ecb_encryption_oracle, KEY_LENGTH, len(PREFIX), len(SECRET_TO_ATTACK))
    assert len(result) == 138
    assert result.startswith("Rollin' in my 5.0")
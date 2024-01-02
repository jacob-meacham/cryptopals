import random
import secrets

from utils.aes import is_aes_ecb, random_key, aes_cbc_encrypt, aes_ecb_encrypt
from utils.pkcs import pkcs7_pad


def aes_encryption_oracle(plaintext: bytes, key: bytes = None):
    rand_prefix = secrets.token_bytes(1) * random.randint(5, 10)
    rand_suffix = secrets.token_bytes(1) * random.randint(5, 10)

    padded_text = pkcs7_pad(rand_prefix + plaintext + rand_suffix, 16)

    if not key:
        key = random_key()
    if random.randint(0, 1) == 0:
        iv = random_key()
        ciphertext = aes_cbc_encrypt(key, pkcs7_pad(padded_text, len(key)), iv)
    else:
        ciphertext = aes_ecb_encrypt(key, pkcs7_pad(padded_text, len(key)))

    return ciphertext


def test_oracle_detection():
    num_ecb = 0
    for _ in range(0, 1000):
        if is_aes_ecb(aes_encryption_oracle(b'A' * 128)):
            num_ecb += 1

    # Should be ~500
    assert 480 < num_ecb < 520

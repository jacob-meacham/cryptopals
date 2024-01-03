import base64
import math
import random

from utils.aes import random_key, aes_ecb_encrypt, is_aes_ecb
from utils.pkcs import pkcs7_pad

KEY_LENGTH = random.choice([16, 32])
SECRET_KEY = random_key(KEY_LENGTH)
SECRET_TO_ATTACK = base64.b64decode(
    'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

def ecb_encryption_oracle(payload: bytes):
    padded_text = pkcs7_pad(payload + SECRET_TO_ATTACK, KEY_LENGTH)
    return aes_ecb_encrypt(SECRET_KEY, padded_text)


def determine_block_and_secret_size() -> (int, int):
    initial_length = len(ecb_encryption_oracle(b''))
    i = 1
    while True:
        payload = b'A' * i
        length = len(ecb_encryption_oracle(payload))
        if length > initial_length:
            return length - initial_length, initial_length - len(payload)
        i += 1


def decrypt_byte(secret_length: int, block_size: int, known_bytes: bytes) -> bytes:
    num_blocks = math.ceil(secret_length / block_size)
    payload_size = num_blocks * block_size

    input = b'A' * (payload_size - len(known_bytes) - 1)

    # We're always pulling off of the final block that makes up our payload
    block_start = (num_blocks - 1) * block_size
    block_end = num_blocks * block_size

    # Generate the map of our payload block + every possible next byte
    bytes_map = {}
    for i in range(256):
        ciphertext = ecb_encryption_oracle(input + known_bytes + bytes([i]))
        bytes_map[ciphertext[block_start:block_end]] = bytes([i])

    # Determine what the next byte actually is
    recovered_block = ecb_encryption_oracle(input)[block_start:block_end]
    return bytes_map[recovered_block]


def break_ecb_encryption_oracle():
    block_size, secret_len = determine_block_and_secret_size()

    assert block_size == KEY_LENGTH
    assert is_aes_ecb(ecb_encryption_oracle(b'A' * 128))

    decrypted_bytes = b''
    for i in range(secret_len):
        decrypted_bytes += decrypt_byte(len(SECRET_TO_ATTACK), block_size, decrypted_bytes)

    return decrypted_bytes.decode()

def test_break_ecb_encryption_oracle():
    result = break_ecb_encryption_oracle()
    assert len(result) == 138
    assert result.startswith("Rollin' in my 5.0")

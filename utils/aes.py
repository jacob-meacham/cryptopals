import secrets
import random
from typing import Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from utils.pkcs import pkcs7_pad
from utils.utils import block_xor


def ensure_aes_constraints(data: bytes, key: bytes, iv=None) -> None:
    block_size = len(key)
    assert len(data) % block_size == 0
    if iv:
        assert len(iv) == block_size


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    ensure_aes_constraints(ciphertext, key)

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    ensure_aes_constraints(plaintext, key)

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    ensure_aes_constraints(plaintext, key, iv)
    block_size = len(key)

    blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    ciphertext = b''

    prev = iv
    for block in blocks:
        xored_block = block_xor(block, prev)
        encrypted = aes_ecb_encrypt(xored_block, key)
        prev = encrypted
        ciphertext += encrypted

    return ciphertext


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    ensure_aes_constraints(ciphertext, key, iv)
    block_size = len(key)

    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = b''

    prev = iv
    for block in blocks:
        decrypted = aes_ecb_decrypt(block, key)
        xored_decrypted = block_xor(decrypted, prev)
        prev = block
        plaintext += xored_decrypted

    return plaintext


def random_key(length: int = 16) -> bytes:
    return secrets.token_bytes(length)


# N.B. Could use a scoring mechanism instead of True/False since false positives are certainly possible
def is_aes_ecb(ciphertext: bytes) -> bool:
    block_size = 16
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    if len(blocks) != len(set(blocks)):
        return True
    return False


def determine_block_and_secret_size(oracle: Callable[[bytes], bytes | str]) -> (int, int):
    initial_length = len(oracle(b'A'))
    i = 2
    while True:
        payload = b'A' * i
        length = len(oracle(payload))
        if length > initial_length:
            return length - initial_length, initial_length - len(payload)
        i += 1


def determine_prefix_length(oracle: Callable[[bytes], bytes], block_size: int) -> int:
    prev_block = oracle(b'A')[:block_size]
    for i in range(2, block_size):
        payload = b'A' * i
        ciphertext = oracle(payload)
        if ciphertext[:block_size] == prev_block:
            return block_size - i + 1
        prev_block = ciphertext[:block_size]

    return 0


def test_aes_decrypt():
    ciphertext = aes_ecb_encrypt(b'YELLOW SUBMARINE', b'YELLOW SUBMARINE')
    plaintext = aes_ecb_decrypt(ciphertext, b'YELLOW SUBMARINE')
    assert plaintext == b'YELLOW SUBMARINE'


def test_cbc_decrypt():
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    original_text = pkcs7_pad(b'Hello darkness my old friend. I\'ve come to talk with you again.', 16)
    ciphertext = aes_cbc_encrypt(original_text, key, iv)
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)

    assert plaintext == original_text


def test_is_aes_ecb():
    ciphertext = aes_ecb_encrypt(b'YELLOW SUBMARINEYELLOW SUBMARINE', b'YELLOW SUBMARINE')
    assert is_aes_ecb(ciphertext) is True

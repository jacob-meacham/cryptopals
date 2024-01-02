import secrets
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from utils.pkcs import pkcs7_pad
from utils.utils import repeating_key_xor


def ensure_aes_constraints(key: bytes, data: bytes, iv=None) -> None:
    block_size = len(key)
    assert len(data) % block_size == 0
    if iv:
        assert len(iv) == block_size


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    ensure_aes_constraints(key, ciphertext)

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    ensure_aes_constraints(key, plaintext)

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    ensure_aes_constraints(key, plaintext, iv)
    block_size = len(key)

    blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    ciphertext = b''

    prev = iv
    for block in blocks:
        xored_block = repeating_key_xor(block, prev)
        encrypted = aes_ecb_encrypt(key, xored_block)
        prev = encrypted
        ciphertext += encrypted

    return ciphertext


def aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    ensure_aes_constraints(key, ciphertext, iv)
    block_size = len(key)

    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = b''

    prev = iv
    for block in blocks:
        decrypted = aes_ecb_decrypt(key, block)
        xored_decrypted = repeating_key_xor(decrypted, prev)
        prev = block
        plaintext += xored_decrypted

    return plaintext


def random_key(length: int = 16) -> bytes:
    return secrets.token_bytes(length)


# TODO: Could use a scoring mechanism instead of True/False since false positives are certainly possible
def is_aes_ecb(ciphertext: bytes) -> bool:
    block_size = 16
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    if len(blocks) != len(set(blocks)):
        return True
    return False


def test_aes_decrypt():
    ciphertext = aes_ecb_encrypt(b'YELLOW SUBMARINE', b'YELLOW SUBMARINE')
    plaintext = aes_ecb_decrypt(b'YELLOW SUBMARINE', ciphertext)
    assert plaintext == b'YELLOW SUBMARINE'


def test_cbc_decrypt():
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    original_text = pkcs7_pad(b'Hello darkness my old friend. I\'ve come to talk with you again.', 16)
    ciphertext = aes_cbc_encrypt(key, original_text, iv)
    plaintext = aes_cbc_decrypt(key, ciphertext, iv)

    assert plaintext == original_text


def test_is_aes_ecb():
    ciphertext = aes_ecb_encrypt(b'YELLOW SUBMARINE', b'YELLOW SUBMARINEYELLOW SUBMARINE')
    assert is_aes_ecb(ciphertext) is True

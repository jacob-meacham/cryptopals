from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


# TODO: Could use a scoring mechanism instead of True/False since false positives are certainly possible
def is_aes_ecb(ciphertext: bytes):
    block_size = 16
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    if len(blocks) != len(set(blocks)):
        return True
    return False
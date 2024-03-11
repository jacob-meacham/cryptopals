import base64

from utils.aes import random_key, aes_cbc_encrypt, aes_cbc_decrypt
from utils.pkcs import pkcs7_pad, pkcs7_unpad, PKCS7ValidationError

DATA = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
            'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
            'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
            'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
            'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
            'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
            'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
            'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
            'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
            'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

SECRET_KEY = random_key()

def oracle_get(id: int) -> (str, str):
    plaintext = base64.b64decode(DATA[id % len(DATA)])

    iv = random_key()
    ciphertext = aes_cbc_encrypt(pkcs7_pad(plaintext, len(SECRET_KEY)), SECRET_KEY, iv).hex()

    return ciphertext, iv.hex()

def oracle_send(ciphertext: str, iv: str):
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    plaintext = aes_cbc_decrypt(ciphertext, SECRET_KEY, iv)
    try:
        pkcs7_unpad(plaintext)
    except PKCS7ValidationError:
        return False

    return True


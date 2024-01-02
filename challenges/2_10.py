import base64

from utils.aes import aes_cbc_decrypt

with open('2_10.txt', 'r') as f:
    ciphertext = ''.join(f.readlines())


key = b'YELLOW SUBMARINE'
iv = b'0x00' * 4
decrypted = aes_cbc_decrypt(key, base64.b64decode(ciphertext), iv)
print(decrypted.decode())

import base64

from utils.aes import aes_ecb_decrypt

key = b'YELLOW SUBMARINE'
with open('1_7.txt', 'r') as f:
    ciphertext = ''.join(f.readlines())

decrypted = aes_ecb_decrypt(base64.b64decode(ciphertext), key)
print(decrypted.decode())

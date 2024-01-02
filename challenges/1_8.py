from utils.aes import aes_ecb_decrypt, is_aes_ecb

ciphertexts = []
with open('1_8.txt', 'r') as f:
    for line in f.readlines():
        ciphertexts.append(line)

aes_ciphertexts = [c for c in ciphertexts if is_aes_ecb(bytes.fromhex(c))]

assert len(aes_ciphertexts) == 1, f'Expected one AES encrypted ciphertext, found {len(aes_ciphertexts)} instead'
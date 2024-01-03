from typing import Dict, Any

from utils.aes import random_key, aes_cbc_encrypt, aes_cbc_decrypt, determine_block_and_secret_size, \
    determine_prefix_length
from utils.pkcs import pkcs7_pad, pkcs7_unpad

KEY_LENGTH = 16
SECRET_KEY = random_key(KEY_LENGTH)
IV = random_key(KEY_LENGTH)

PREFIX = 'comment1=cooking%20MCs;userdata='
SUFFIX = ';comment2=%20like%20a%20pound%20of%20bacon'


def server_set_user_data(user_data: str) -> str:
    user_data = user_data.replace(';', '_').replace('=', '_')
    data = PREFIX + user_data + SUFFIX

    # Take and return string here to simulate what a server might actually send back
    return aes_cbc_encrypt(pkcs7_pad(data.encode(), len(SECRET_KEY)), SECRET_KEY, IV).hex()

def parse_user(from_str: str) -> Dict[str, str]:
    result = {}
    for item in from_str.split(';'):
        key, value = item.split('=')
        result[key] = value

    return result

def server_parse_user(ciphertext: str) -> Dict[str, str]:
    plaintext = pkcs7_unpad(aes_cbc_decrypt(bytes.fromhex(ciphertext), SECRET_KEY, IV))

    # Bad dev, don't do it this way!
    user = parse_user(str(plaintext)[2:-1])

    return user


def oracle(data: bytes) -> bytes:
    return bytes.fromhex(server_set_user_data(data.decode()))


def bit_flip_attack():
    block_size, secret_size = determine_block_and_secret_size(oracle)
    assert block_size == 16
    assert secret_size == len(PREFIX) + len(SUFFIX)

    # TODO: Is it possible to determine the prefix length if it is longer than a block?
    admin_str = '_admin_true'
    garbage_block = 'A' * block_size
    attack_data = 'A' * (block_size - len(admin_str))
    user_data = garbage_block + attack_data + admin_str  # Single block with admin

    # Construct what we're hoping to achieve
    target = 'comment1=cooking%20MCs;userdata='
    target += user_data
    target += ';comment2=%20like%20a%20pound%20of%20bacon'
    target = pkcs7_pad(target.encode(), block_size)
    target_blocks = [target[i:i + block_size] for i in range(0, len(target), block_size)]

    ciphertext = bytes.fromhex(server_set_user_data(user_data))
    ciphertext_blocks = [bytearray(ciphertext[i:i + block_size]) for i in range(0, len(ciphertext), block_size)]

    # Flip the bits in the ciphertext blocks to get the desired plaintext
    attack_block = 2
    target_block = 3
    to_semi = len(attack_data)
    to_equals = len(attack_data) + 6

    ciphertext_blocks[attack_block][to_semi] = ciphertext_blocks[attack_block][to_semi] ^ ord(';') ^ \
                                                target_blocks[target_block][to_semi]
    ciphertext_blocks[attack_block][to_equals] = ciphertext_blocks[attack_block][to_equals] ^ ord('=') ^ \
                                               target_blocks[target_block][to_equals]

    # Construct the modified ciphertext
    modified_ciphertext = b''.join(ciphertext_blocks)

    return server_parse_user(modified_ciphertext.hex())


def test_bit_flip_attack():
    user = bit_flip_attack()
    assert user['comment1'] == 'cooking%20MCs'
    assert user['comment2'] == '%20like%20a%20pound%20of%20bacon'
    assert user['admin'] == 'true'
    assert 'userdata' in user

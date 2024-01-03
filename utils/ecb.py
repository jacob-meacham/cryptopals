import math
from typing import Callable

from utils.aes import is_aes_ecb, determine_block_and_secret_size, determine_prefix_length


def decrypt_byte(oracle: Callable[[bytes], bytes], secret_length: int, block_size: int, padding_length: int, known_bytes: bytes) -> bytes:
    num_payload_blocks = math.ceil(secret_length / block_size)
    payload_size = num_payload_blocks * block_size
    total_blocks = num_payload_blocks + math.ceil(padding_length / block_size)
    pad_to_block = (block_size - padding_length) % block_size

    input = b'A' * (pad_to_block + payload_size - len(known_bytes) - 1)

    # We're always pulling off of the final block that makes up our payload
    block_start = (total_blocks - 1) * block_size
    block_end = total_blocks * block_size

    # Generate the map of our payload block + every possible next byte
    bytes_map = {}
    for i in range(256):
        ciphertext = oracle(input + known_bytes + bytes([i]))
        bytes_map[ciphertext[block_start:block_end]] = bytes([i])

    # Determine what the next byte actually is
    recovered_block = oracle(input)[block_start:block_end]
    return bytes_map[recovered_block]


def break_ecb_encryption_oracle(oracle: Callable[[bytes], bytes], key_length: int, prefix_length: int, secret_length: int):
    block_size, secret_len = determine_block_and_secret_size(oracle)

    assert block_size == key_length
    assert is_aes_ecb(oracle(b'A' * 128))

    # Determine if there is any padding at the beginning
    padding_length = determine_prefix_length(oracle, block_size)
    assert padding_length == prefix_length

    secret_len -= padding_length
    assert secret_len == secret_length

    decrypted_bytes = b''
    for i in range(secret_len):
        decrypted_bytes += decrypt_byte(oracle, secret_len, block_size, padding_length, decrypted_bytes)

    return decrypted_bytes.decode()
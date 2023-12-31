import base64
from itertools import zip_longest

from utils.english_language import MOST_COMMON
from utils.utils import hamming_distance, single_byte_xor_cipher, repeating_key_xor, hamming_distance_arr, \
    score_string_by_hist


def attack_with_keysize(encoded: bytes, keysize: int) -> str:
    blocks = [encoded[i:i + keysize] for i in range(0, len(encoded), keysize)]
    transposed_blocks = [[block[i] for block in blocks if len(block) > i] for i in range(keysize)]

    # Perform single-byte XOR cipher on each block
    best_keys = []
    for block in transposed_blocks:
        d = single_byte_xor_cipher(block)
        best_keys.append(d[0]['key'])

    # Combine the most likely key for each position
    key = b''.join(best_keys)

    # Decrypt the encoded message using the key
    return repeating_key_xor(encoded, key).decode()


def attack_repeating_key_xor(encoded: bytes, keysize_range: tuple) -> str:
    # Find the best keysize
    keysizes = range(keysize_range[0], keysize_range[1])
    best_keysizes = sorted(keysizes, key=lambda k: hamming_distance_arr([encoded[i * k:(i + 1) * k] for i in range(4)]) / k)

    # Try the top 5 keysizes
    decoded_messages = [attack_with_keysize(encoded, keysize) for keysize in best_keysizes[0:5]]
    decoded_messages.sort(key=lambda message:score_string_by_hist(message, MOST_COMMON), reverse=True)

    return decoded_messages[0]


def test_attack_repeating_key_xor():
    s1 = attack_repeating_key_xor(bytes.fromhex(
        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'),
                                  (2, 10))
    print(s1)


if __name__ == '__main__':
    with open('6.txt', 'r') as f:
        input = ''.join(f.readlines())

    encoded_message = base64.b64decode(input)
    decrypted = attack_repeating_key_xor(encoded_message, (2, 40))
    print(decrypted)
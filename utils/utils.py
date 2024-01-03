import base64
import itertools
from typing import Callable, Any, Dict

from utils.english_language import MOST_COMMON


def convert_hex_to_b64(hex_s: str) -> str:
    b64 = base64.b64encode(bytes.fromhex(hex_s))
    return b64.decode('utf-8')


def block_xor(b1: bytes, b2: bytes) -> bytes:
    return bytes([a ^ b for a, b in zip(b1, itertools.cycle(b2))])


def hamming_distance(b1: bytes, b2: bytes) -> int:
    return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))


def hamming_distance_arr(l: list[bytes]) -> float:
    distances = [hamming_distance(b1, b2) for b1, b2 in itertools.pairwise(l)]
    return sum(distances) / len(distances)


# N.B. Very basic scoring mechanism
def score_string_by_hist(s: str, hist: dict) -> float:
    score = 0

    for char in s:
        if char in hist:
            score += hist[char]

    return score
    # counter = Counter()
    # for char in s:
    #     if char in hist:
    #         counter[char.upper()] += 1
    #     else:
    #         counter['_'] += 1
    #
    # text_rel_freqs = {k: {
    #     'frequency': v,
    #     'rel_freq': v / len(s)
    # } for k, v in counter.items()}
    #
    # score = 0.0
    # for k, v in text_rel_freqs.items():
    #     if k in hist:
    #         expected_freq = hist[k]['rel_freq'] / v['frequency']
    #     else:
    #         expected_freq = 0.0
    #     score += (expected_freq - v['rel_freq'])
    #
    # return abs(score)


def single_byte_xor_cipher(message: bytes | list[int], scoring_fn: Callable[[str, dict], float] = score_string_by_hist) -> list[
    Dict[str, Any]]:

    decoded_messages = []
    for key in range(256):
        try:
            decoded_message = block_xor(message, key.to_bytes()).decode()
            decoded_messages.append({'key': key.to_bytes(),
                                     'value': decoded_message, 'score': scoring_fn(decoded_message, MOST_COMMON)})
        except UnicodeDecodeError:
            pass

    decoded_messages.sort(key=lambda x: x['score'], reverse=True)
    return decoded_messages


def test_convert_hex_to_b64():
    hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    result = convert_hex_to_b64(hex_string)

    assert result == expected_result, f"For hex '{hex_string}', expected b64 '{expected_result}' but got '{result}'"


def test_repeating_key_xor():
    expected_result = bytes.fromhex("746865206b696420646f6e277420706c6179")

    s1 = '1c0111001f010100061a024b53535009181c'
    key = '686974207468652062756c6c277320657965'
    result = block_xor(bytes.fromhex(s1), bytes.fromhex(key))

    assert result == expected_result, f"For s1 '{s1}' and key '{key}', expected result '{expected_result.hex()}' but got '{result.hex()}'"


def test_repeating_key_xor_inverse():
    s1 = 'It was the best of times, it was the worst of times'
    key = b'MY SECRET KEY'

    encoded = block_xor(s1.encode(), key)
    decoded = block_xor(encoded, key).decode('ascii')

    assert decoded == s1, f'For key {key}, expected {s1}, got {decoded}'


def test_hamming_distance():
    b1 = b'this is a test'
    b2 = b'wokka wokka!!!'
    result = hamming_distance(b1, b2)
    assert result == 37, f"For b1 '{b1}' and b2 '{b2}', expected distance 8 but got {result}"

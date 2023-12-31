# https://www.cryptopals.com/sets/1/challenges/3
from utils.utils import single_byte_xor_cipher


def test_single_byte_xor_cipher():
    assert single_byte_xor_cipher(bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))[0]['value'] == "Cooking MC's like a pound of bacon"

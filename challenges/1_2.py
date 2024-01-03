# https://www.cryptopals.com/sets/1/challenges/2
from utils.utils import block_xor


def test_xor():
    assert block_xor(bytes.fromhex('1c0111001f010100061a024b53535009181c'),
                     bytes.fromhex('686974207468652062756c6c277320657965')).hex() == '746865206b696420646f6e277420706c6179'

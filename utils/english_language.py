from collections import Counter
from functools import cache

from nltk.corpus import brown

MOST_COMMON = {
    ' ': 16, 'e': 15, 't': 14, 'a': 13, 'o': 12, 'i': 11, 'n': 10, 's': 9, 'h': 8, 'r': 7, 'd': 6, 'l': 5, 'u': 4
}

@cache
def english_language_letter_freqs() -> dict:
    s = ' '.join(brown.words()[:30000])

    counter = Counter()
    for char in s:
        counter[char] += 1

    text_rel_freqs = {k: {
        'frequency': v,
        'rel_freq': v / len(s)
    } for k, v in counter.items()}

    return text_rel_freqs

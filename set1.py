#!/usr/bin/env python

import base64
import binascii
import string


def hex2bin(hexStr):
    return bytearray(binascii.unhexlify(hexStr))


def b64(data):
    return base64.b64encode(data)


assert b64(hex2bin("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


def fixed_xor(buf1, buf2):
    assert len(buf1) == len(buf2)
    message = bytearray()
    for i, c in enumerate(buf1):
        message.append(c ^ buf2[i])
    return message


assert fixed_xor(hex2bin("1c0111001f010100061a024b53535009181c"), hex2bin("686974207468652062756c6c277320657965")) == hex2bin("746865206b696420646f6e277420706c6179")


def other_char_score(char):
    char = char.lower()
    # http://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
    matrix = {'a': 8.167,
              'b': 1.492,
              'c': 2.782,
              'd': 4.253,
              'e': 12.702,
              'f': 2.228,
              'g': 2.015,
              'h': 6.094,
              'i': 6.966,
              'j': 0.153,
              'k': 0.772,
              'l': 4.025,
              'm': 2.406,
              'n': 6.749,
              'o': 7.507,
              'p': 1.929,
              'q': 0.095,
              'r': 5.987,
              's': 6.327,
              't': 9.056,
              'u': 2.758,
              'v': 0.978,
              'w': 2.360,
              'x': 0.150,
              'y': 1.974,
              'z': 0.074}

    freq = matrix.get(char, 0)
    return freq

def first_char_score(char):
    char = char.lower()
    # http://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_the_first_letters_of_a_word_in_the_English_language
    # represented as frequency(percentage)
    matrix = {'a': 11.602,
              'b': 4.702,
              'c': 3.511,
              'd': 2.670,
              'e': 2.007,
              'f': 3.779,
              'g': 1.950,
              'h': 7.232,
              'i': 6.286,
              'j': 0.597,
              'k': 0.590,
              'l': 2.705,
              'm': 4.374,
              'n': 2.365,
              'o': 6.264,
              'p': 2.545,
              'q': 0.173,
              'r': 1.653,
              's': 7.755,
              't': 16.671,
              'u': 1.487,
              'v': 0.649,
              'w': 6.753,
              'x': 0.017,
              'y': 1.620,
              'z': 0.034}

    freq = matrix.get(char, 0)
    return freq

def english_score(str):
    # default score is 0
    score = 0

    # english consists of words separated by whitespace(whoah)
    words = str.split()

    for word in words:
        # first character of english words have a certain frequency
        score += first_char_score(chr(word[0]))

        # then for the others...
        for i, c in enumerate(word[1:]):
            c = chr(c)
            # punctuation in the middle of an english word is uncommon
            # let's decrement score(need to determine by how much)
            if c in string.punctuation and i + 2 != len(word):
                # unless it's a possessive...
                if i + 3 == len(word) and chr(word[i+2]) == 's':
                    continue

                # or contraction with apostrophe(they're)
                if i + 4 == len(word) and (chr(word[i+2]) + chr(word[i+3])) == 're':
                    continue

                score -= 10
            else:
                score += other_char_score(c)

    return score

def brute_force_xor(hexStr):
    _l = len(hex2bin(hexStr))
    scores = {}

    for c in string.printable:
        result = fixed_xor(hex2bin(hexStr), hex2bin(binascii.b2a_hex(c) * _l))
        scores[c] = english_score(result)

    maxScore = 0
    for char, score in scores.iteritems():
        if score > maxScore:
            maxScore = score
            maxChar = char

    print "brute forced, best score was char", maxChar, "with score", maxScore
    print "produced string..."
    print fixed_xor(hex2bin(hexStr), hex2bin(binascii.b2a_hex(maxChar) * _l))

brute_force_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
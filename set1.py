#!/usr/bin/env python

from __future__ import division

import base64
import binascii
import string
import math
from sets import Set


TEST_ASSERTIONS = False


def hex2bin(hexStr):
    return bytearray(binascii.unhexlify(hexStr))


def b64(data):
    return base64.b64encode(data)


if TEST_ASSERTIONS:
    assert b64(hex2bin("49276d206b696c6c696e6720796f75722062726169"
                       "6e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")) \
        == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


def repeating_xor(buf, key):
    message = bytearray()
    assert type(buf) == type(message) and type(key) == type(message)

    _l = len(buf)

    # pad key out to full length
    keyPad = bytearray(key * int(math.ceil(_l / len(key))))
    if len(keyPad) > _l:
        keyPad = keyPad[:_l]
    assert len(keyPad) == _l

    for i, c in enumerate(buf):
        message.append(c ^ keyPad[i])

    return message


def fixed_xor(buf1, buf2):
    assert len(buf1) == len(buf2)
    message = bytearray()
    for i, c in enumerate(buf1):
        message.append(c ^ buf2[i])
    return message


if TEST_ASSERTIONS:
    assert fixed_xor(hex2bin("1c0111001f010100061a024b53535009181c"),
                     hex2bin("686974207468652062756c6c277320657965")) \
        == hex2bin("746865206b696420646f6e277420706c6179")


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
    #print str
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
                if i + 3 == len(word) and chr(word[i + 2]) == 's':
                    continue

                # or contraction with apostrophe(they're)
                if i + 4 == len(word) and (chr(word[i + 2]) +
                                           chr(word[i + 3])) == 're':
                        continue

                score -= 10
            elif c not in string.printable:
                score -= 50
            else:
                score += other_char_score(c)

    return score


def brute_force_xor(bytes):
    _l = len(bytes)
    scores = {}

    for c in string.printable:
        result = fixed_xor(bytes, hex2bin(binascii.b2a_hex(c) * _l))
        scores[c] = english_score(result)

    maxChar = None
    maxScore = None
    for char, score in scores.iteritems():
        if maxScore is None or score > maxScore:
            maxScore = score
            maxChar = char

    return {'char': maxChar, 'score': maxScore, 'result':
            fixed_xor(bytes, hex2bin(binascii.b2a_hex(maxChar) * _l))}

if TEST_ASSERTIONS:
    assert brute_force_xor(hex2bin("1b37373331363f78151b7f2b783431333d78397828372d"
                                   "363c78373e783a393b3736")) == \
        {'char': 'X', 'score': 145.468, 'result': bytearray(b"Cooking MC\'s like a"
                                                             " pound of bacon")
        }


def challenge_4():
    lines = []
    with open('4.txt', 'r') as f:
        for line in f:
            line = line.strip()
            lines.append(hex2bin(line))

    return brute_force_xor_chunks(lines)


def brute_force_xor_chunks(lines):
    scores = []
    for line in lines:
        scores.append(brute_force_xor(line))

    maxScore = 0
    candidate = None
    for s in scores:
        if s['score'] > maxScore:
            maxScore = s['score']
            candidate = s

    return candidate

if TEST_ASSERTIONS:
    assert challenge_4() == {'char': '5', 'score': 151.449, 'result':
                             bytearray(b'Now that the party is jumping\n')}

if TEST_ASSERTIONS:
    assert repeating_xor(hex2bin(binascii.hexlify("Burning 'em, if you ain't quick"
                                                  " and nimble\nI go crazy when I "
                                                  "hear a cymbal")),
                         hex2bin(binascii.hexlify("ICE"))) == \
        hex2bin("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632"
                "4272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b202831"
                "65286326302e27282f")


def edit_dist(str1, str2):
    assert len(str1) == len(str2)
    xor = fixed_xor(bytearray(str1), bytearray(str2))
    binary = ' '.join(format(b, 'b') for b in xor)
    _sum = binary.count('1')
    return _sum


def chunkify(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i + n]


def transpose(chunks, sz):
    transposition = []
    for i in range(1, sz):
        trans_block = bytearray()
        for block in chunks:
            if len(block) != sz - 1:
                continue

            trans_block.append(block[i - 1])

        transposition.append(trans_block)

    return transposition


if TEST_ASSERTIONS:
    assert transpose([bytearray("assp"), bytearray("burg"), bytearray("gers")], 5)\
        == [bytearray("abg"), bytearray("sue"), bytearray("srr"), bytearray("pgs")]


def bruteforce_keysize(bytes, desired_keysizes):
    keysizes = Set()
    while len(keysizes) != desired_keysizes:
        for keysize in range(1, int(len(bytes) / 2)):
            # 3.
            str1 = bytes[:keysize]
            str2 = bytes[keysize:keysize * 2]
            dist = edit_dist(str1, str2)
            norm = dist / (keysize * 8)
            keysizes.add((keysize, norm))
        keysizes = sorted(keysizes, key=lambda item: item[1])
        if len(keysizes) > desired_keysizes:
            keysizes = keysizes[:desired_keysizes]
        print keysizes

    return [k[0] for k in keysizes]


def challenge_6():
    b64 = ''
    with open('6.txt', 'r') as f:
        for line in f:
            line = line.strip()
            b64 += line

    bytes = base64.b64decode(b64)

    # XXX try few smallest potential keysizes
    keysizes = []
    desired_keysizes = 5
    # 1.
    keysizes = bruteforce_keysize(bytes, desired_keysizes)

    for favKeysize in keysizes:
        print "Working with keysize", favKeysize
        chunks = []
        # 5.
        # chunk encrypted data into keysize-sized chunks
        for chunk in chunkify(bytes, favKeysize):
            chunks.append(chunk)

        key = []
        # 6.
        # transpose the keysize-sized chunks to produce a keysize-long array
        # containing the 1..keysize'th elements of each block
        transposition = transpose(chunks, favKeysize + 1)

        # now we have each position of the candidate key to iterate through --
        for block in transposition:
            for c in string.printable:
                result = repeating_xor(block, hex2bin(binascii.b2a_hex(c) * favKeysize))
                print result
                score = english_score(result)
                if score > 0:
                    print score

            key.append(brute_force_xor(block))

        print key

        for c in key:
            print c['char']

    return bytearray(''.join([c['char'] for c in key]))


if TEST_ASSERTIONS:
    assert edit_dist("this is a test", "wokka wokka!!!") == 37

key = challenge_6()
b64 = ''
bytes = ''
with open('6.txt', 'r') as f:
    for line in f:
        line = line.strip()
        b64 += line

bytes = bytearray(base64.b64decode(b64))

print "KEY:", repr(key)
print "ENCRYPTED DATA:", repr(bytes)
print "DECRYPTED DATA:", repr(repeating_xor(bytes, key))


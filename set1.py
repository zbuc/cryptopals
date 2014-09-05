#!/usr/bin/env python

from __future__ import division

import base64
import binascii
import string
import math
from collections import Counter


TEST_ASSERTIONS = True

# http://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
WORD_LETTER_FREQS = {'a': 8.167,
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

FIRST_CHAR_FREQS = {'a': 11.602,
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


# load our word list into memory, sorted by length
wordlist = {}
with open('./wordsEn.txt', 'r') as f:
    for line in f:
        line = line.strip()
        arr = wordlist.get(len(line), [])
        arr.append(line)
        wordlist[len(line)] = arr


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

    freq = WORD_LETTER_FREQS.get(char.lower(), 0)
    return freq


def first_char_score(char):
    char = char.lower()
    # http://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_the_first_letters_of_a_word_in_the_English_language
    # represented as frequency(percentage)

    freq = FIRST_CHAR_FREQS.get(char.lower(), 0)
    return freq


# Source:
# http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
ENGLISH_FREQUENCIES = {
    'E': .1202,
    'T': .0910,
    'A': .0812,
    'O': .0768,
    'I': .0731,
    'N': .0695,
    'S': .0628,
    'R': .0602,
    'H': .0592,
    'D': .0432,
    'L': .0398,
    'U': .0288,
    'C': .0271,
    'M': .0261,
    'F': .0230,
    'Y': .0211,
    'W': .0209,
    'G': .0203,
    'P': .0182,
    'B': .0149,
    'V': .0111,
    'K': .0069,
    'X': .0017,
    'Q': .0011,
    'J': .0010,
    'Z': .0007,
}


def partition(pred, iterable):
    "Return a pair of lists; elements that satisfy pred, and those that don't."
    # No cuteness because I only want to inspect each element once.
    sat = []
    unsat = []
    for e in iterable:
        if pred(e):
            sat.append(e)
        else:
            unsat.append(e)
    return sat, unsat


def english_score(str, not_sentence=False):
    #print str
    # default score is 0
    score = 0

    # english consists of words separated by whitespace(whoah)
    if not not_sentence:
        words = str.split()
    else:
        words = [str]

    for word in words:
        if not not_sentence:
            # first character of english words have a certain frequency
            score += first_char_score(chr(word[0]))

        enumerable = enumerate(word[1:])
        factor = None
        if not_sentence:
            enumerable = enumerate(word)

            letters, other = partition(lambda c: chr(c) in ENGLISH_FREQUENCIES, word)

            if not letters:
                break

            spaces, other = partition(lambda c: chr(c).isspace(), other)

            # Expect roughly 15% of text to be spaces.
            space_error = len(spaces) / len(word) - 0.15

            # As a rough approximation, expect 2% of characters to be punctuation.
            punc_error = len(other) / len(word) - 0.02

            counts = Counter(word)
            letter_error = 0.0
            for c, target_freq in ENGLISH_FREQUENCIES.items():
                letter_error += (target_freq *
                                counts.get(ord(c), 0)/len(letters) - target_freq)
            factor = max(1.0 - (punc_error + letter_error + space_error), 0.0)

        for i, c in enumerable:
            c = chr(c)
            # punctuation in the middle of an english word is uncommon
            # let's decrement score(need to determine by how much)
            if c in string.punctuation and i + 2 != len(word):
                if not_sentence:
                    continue

                # unless it's a possessive...
                if i + 3 == len(word) and chr(word[i + 2]) == 's':
                    continue

                # or contraction with apostrophe(they're)
                if i + 4 == len(word) and (chr(word[i + 2]) +
                                           chr(word[i + 3])) == 're':
                        continue

                score -= 10
            elif c not in string.printable:
                score -= 20
            elif c in string.whitespace:
                pass
            else:
                score += other_char_score(c)

    if factor:
        score = score * factor

    return score


def brute_force_xor(bytes, not_sentence=False):
    _l = len(bytes)
    scores = {}

    for c in string.printable:
        result = fixed_xor(bytes, hex2bin(binascii.b2a_hex(c) * _l))
        scores[c] = english_score(result, not_sentence=not_sentence)

    desired = 3
    maxChars = []
    for char, score in scores.iteritems():
        maxChars.append((char, score))

    maxChars = sorted(maxChars, key=lambda item: item[1])
    maxChars.reverse()
    maxChars = maxChars[:desired]

    ret = []
    for char in maxChars:
        ret.append({'char': char[0], 'score': char[1], 'result':
                fixed_xor(bytes, hex2bin(binascii.b2a_hex(char[0]) * _l))})

    for r in ret:
        if r['score'] > 0:
            print r
    if False:
        maxScore = None
        chosen = None
        for r in ret:
            # check each word against dictionary. 1 point for hit. pick best scored
            score = 0
            for word in r['result'].split():
                if word in wordlist.get(len(word), []):
                    pass
                    #score += 1

            if maxScore is None or score > maxScore:
                maxScore = score
                chosen = r

        if not chosen:
            print "Well fuk"
        return chosen
    return ret[0]


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
        score = brute_force_xor(line)
        if score:
            scores.append(score)

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
    keysizes = []
    while len(keysizes) != desired_keysizes:
        for keysize in range(1, int(len(bytes) / 2)):
            # 3.
            str1 = bytes[:keysize]
            str2 = bytes[keysize:keysize * 2]
            dist = edit_dist(str1, str2)
            norm = dist / (keysize * 8)
            keysizes.append((keysize, norm))
        keysizes = sorted(keysizes, key=lambda item: item[1])
        keysizes.reverse()
        if len(keysizes) > desired_keysizes:
            keysizes = keysizes[:desired_keysizes]

    return [k[0] for k in keysizes]


def get_word_count(sentence):
    # check each word against dictionary. 1 point for hit. pick best scored
    score = 0
    for word in sentence.split():
        if word in wordlist.get(len(word), []):
            print word
            print wordlist.get(len(word))
            score += 1

    return score


def challenge_6():
    b64 = ''
    with open('6.txt', 'r') as f:
        for line in f:
            line = line.strip()
            b64 += line

    bytes = bytearray(base64.b64decode(b64))

    # XXX try few smallest potential keysizes
    keysizes = []
    desired_keysizes = 10
    # 1.
    keysizes = bruteforce_keysize(bytes, desired_keysizes)

    candidate_keys = []
    for favKeysize in keysizes:
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
            key.append(brute_force_xor(block, not_sentence=True))

        candidate_keys.append(bytearray(''.join([c['char'] for c in key])))

    for k in candidate_keys:
        print k
        print type(bytes)
        print type(k)
        result = repeating_xor(bytes, k)
        print result
        score = get_word_count(result)
        print score



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

# try replacing characters from key and see if scoring for
# decrypted text improves or not
print "KEY:", key
print "DECRYPTED DATA:", repeating_xor(bytes, key)

#!/usr/bin/env python3

import pytest
import bip39
import json
import pathlib
import os

####################################################################################################

def get_test_vector():
    # This vector was based in https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    # The passphrase "TREZOR" is used for all vectors
    script_directory = pathlib.Path(__file__).parent.resolve()
    with open(os.path.join(script_directory, 'bip39_vector.json'), 'r', encoding='utf-8') \
            as file:
        # Use English words
        # Indexes:
        #  0: Entropy in hex
        #  1: Checksum in hex
        #  2: Sentence
        #  3: List of keys related to sentence
        #  4: Seed
        return json.load(file)['english']

####################################################################################################
####################################################################################################

def test_load_wordlist():
    assert len(bip39.WORDS_LIST_EN) == 0
    bip39.load_wordlist()
    assert len(bip39.WORDS_LIST_EN) == 2048

####################################################################################################

def test_word_is_valid():
    # Load word list
    bip39.load_wordlist()

    # Iterate over all words
    for word in bip39.WORDS_LIST_EN:
        # Verify all words are valid
        assert bip39.word_is_valid(word) == True

        # Verify a valid word, but upper case, is invalid
        assert bip39.word_is_valid(word.upper()) == False

    # Verify None is invalid
    assert bip39.word_is_valid(None) == False

    # Verify empty is invalid
    assert bip39.word_is_valid('') == False

    # Verify a random word is invalid
    assert bip39.word_is_valid('jung') == False

####################################################################################################

def test_sentence_is_valid():
    # Load word list
    bip39.load_wordlist()

    # Load test vector
    test_vector = get_test_vector()

    # Iterate over all sentences
    for sentence in test_vector:
        # Verify sentence is valid
        assert bip39.sentence_is_valid(sentence[2]) == True

        # Verify upper case sentence is not valid
        assert bip39.sentence_is_valid(sentence[2].upper()) == False

    # Modify last word of first sentence and verify it is not valid.
    # First sentence is 'abandon abandon ... about'. Change last word to abandon too.
    sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    assert bip39.sentence_is_valid(sentence) == True
    sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    assert bip39.sentence_is_valid(sentence) == False

####################################################################################################

def test_sentence_to_seed():
    # Load word list
    bip39.load_wordlist()

    # Load test vector
    test_vector = get_test_vector()

    # Iterate over all sentences
    for sentence in test_vector:
        # Verify sentence_is_valid()
        assert bip39.sentence_to_seed(sentence[2], 'TREZOR').hex() == sentence[4]

####################################################################################################

def test_words_to_sentence():
    # Load word list
    bip39.load_wordlist()

    # Verify list of valid words
    valid_words = [
        "letter",
        "advice",
        "cage",
        "absurd",
        "amount",
        "doctor",
        "acoustic",
        "avoid",
        "letter",
        "advice",
        "cage",
        "absurd"
    ]
    assert bip39.words_to_sentence(valid_words) \
            == "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd"

    # Verify list of words with an invalid one
    invalid_words = [
        "lerer",
        "advice",
        "cage",
        "absurd",
        "amount",
        "doctor",
        "acoustic",
        "avoid",
        "letter",
        "advice",
        "cage",
        "absurd"
    ]
    with pytest.raises(ValueError, match="Invalid word"):
        bip39.words_to_sentence(invalid_words)

####################################################################################################

def test_indexes_list_to_words_list():
    # Load word list
    bip39.load_wordlist()

    # Verify valid indexes
    assert bip39.indexes_list_to_words_list([0, 1, 2047 ]) == ["abandon", "ability", "zoo"]

    # Verify invalid indexes
    with pytest.raises(IndexError, match="list index out of range"):
        bip39.indexes_list_to_words_list([0, 1, 2048 ])

####################################################################################################

def test_get_entropy_bit_length():
    # BIP39 Definition:
    # The following table describes the relation between the initial entropy length (ENT) and
    # mnemonic sentence (MS) in words.
    #
    # |  ENT  |  MS  |
    # +-------+------+
    # |  128  |  12  |
    assert bip39.get_entropy_bit_length() == 128
    assert bip39.get_entropy_bit_length(12) == 128
    # |  160  |  15  |
    assert bip39.get_entropy_bit_length(15) == 160
    # |  192  |  18  |
    assert bip39.get_entropy_bit_length(18) == 192
    # |  224  |  21  |
    assert bip39.get_entropy_bit_length(21) == 224
    # |  256  |  24  |
    assert bip39.get_entropy_bit_length(24) == 256

    # Invalid values
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 0"):
        bip39.get_entropy_bit_length(0)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 1"):
        bip39.get_entropy_bit_length(1)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 2"):
        bip39.get_entropy_bit_length(2)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 3"):
        bip39.get_entropy_bit_length(3)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 4"):
        bip39.get_entropy_bit_length(4)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 5"):
        bip39.get_entropy_bit_length(5)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 6"):
        bip39.get_entropy_bit_length(6)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 7"):
        bip39.get_entropy_bit_length(7)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 8"):
        bip39.get_entropy_bit_length(8)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 9"):
        bip39.get_entropy_bit_length(9)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 10"):
        bip39.get_entropy_bit_length(10)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 11"):
        bip39.get_entropy_bit_length(11)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 13"):
        bip39.get_entropy_bit_length(13)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 14"):
        bip39.get_entropy_bit_length(14)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 16"):
        bip39.get_entropy_bit_length(16)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 17"):
        bip39.get_entropy_bit_length(17)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 19"):
        bip39.get_entropy_bit_length(19)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 20"):
        bip39.get_entropy_bit_length(20)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 22"):
        bip39.get_entropy_bit_length(22)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 23"):
        bip39.get_entropy_bit_length(23)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 25"):
        bip39.get_entropy_bit_length(25)
    with pytest.raises(ValueError, match="Invalid mnemonic_sentence_size of 26"):
        bip39.get_entropy_bit_length(26)

####################################################################################################

def test_entropy_checksum_to_indexes_list():
    # Load word list
    bip39.load_wordlist()

    # Load test vector
    test_vector = get_test_vector()

    # Iterate over all sentences
    for sentence in test_vector:
        num_of_indexes = len(sentence[2].split(' '))
        entropy_len_bits = bip39.get_entropy_bit_length(num_of_indexes)
        checksum_len_bits = bip39.get_checksum_length(entropy_len_bits)

        # Mount entry + checksum
        entropy = int(sentence[0], 16)
        checksum = int(sentence[1], 16)
        entropy_and_checksum = (entropy << checksum_len_bits) | checksum

        # Verify entropy_checksum_to_indexes_list()
        assert bip39.entropy_checksum_to_indexes_list(entropy_and_checksum, num_of_indexes) \
                == sentence[3]

####################################################################################################

def test_get_checksum_length():
    # BIP39 Definition:
    # Checksum length is entropy_len / 32
    assert bip39.get_checksum_length(0) == 0
    assert bip39.get_checksum_length(31) == 0
    assert bip39.get_checksum_length(32) == 1
    assert bip39.get_checksum_length(33) == 1
    assert bip39.get_checksum_length(63) == 1
    assert bip39.get_checksum_length(64) == 2
    assert bip39.get_checksum_length(65) == 2
    assert bip39.get_checksum_length(95) == 2
    assert bip39.get_checksum_length(96) == 3

####################################################################################################

def test_get_entropy_checksum():
    # Load word list
    bip39.load_wordlist()

    # Load test vector
    test_vector = get_test_vector()

    # Iterate over all sentences
    for sentence in test_vector:
        num_of_indexes = len(sentence[2].split(' '))
        entropy_len_bits = bip39.get_entropy_bit_length(num_of_indexes)
        entropy_len_bytes = int(entropy_len_bits / 8)

        # Verify get_entropy_checksum()
        assert bip39.get_entropy_checksum(int(sentence[0], 16), entropy_len_bytes) \
                == int(sentence[1], 16)

####################################################################################################

def test_generate_sentence_from_entropy():
    # Load word list
    bip39.load_wordlist()

    # Load test vector
    test_vector = get_test_vector()

    # Iterate over all sentences
    for sentence in test_vector:
        num_of_words = len(sentence[2].split(' '))
        # Verify that function convert entropy to sentence correctly
        assert bip39.generate_sentence_from_entropy(int(sentence[0], 16), num_of_words) \
                == sentence[2].split(' ')

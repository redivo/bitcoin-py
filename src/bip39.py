#!/usr/bin/env python3

"""
Implementation of BIP39.
Please refer to https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki.
"""

import secrets
import hashlib
import pathlib
import os
import argparse

WORDS_LIST_EN = []

####################################################################################################

def load_wordlist():
    """
    Load English wordlist Generate a random words list based on official BIP39 words.
    The loaded list is put in global variable WORDS_LIST_EN
    """

    # Use WORDS_LIST_EN as global
    # pylint: disable-next=global-statement
    global WORDS_LIST_EN

    # Load wordlist
    script_directory = pathlib.Path(__file__).parent.resolve()
    with open(os.path.join(script_directory, 'bip39-english-wordlist.txt'), 'r', encoding='utf-8') \
            as file:
        WORDS_LIST_EN = [line.strip() for line in file]

####################################################################################################

def word_is_valid(word):
    """
    Verify if a word is part of official English BIP39 words list.

    Parameters:
        word (str): Word to be verified

    Return:
        True if the given word is valid, False otherwise
    """

    # Word must be part of WORDS_LIST_EN
    return word in WORDS_LIST_EN

####################################################################################################

def sentence_is_valid(sentence):
    """
    Verify if a sentence is valid considering official English BIP39 words list.

    Parameters:
        sentence (str): Sentence with space separated words

    Return:
        True if the given sentence is valid, False otherwise
    """

    # Split sentence by blank space to check word by word
    words = sentence.split(' ')
    number_of_words = len(words)

    # Iterate over all words. If it is not valid, return False. Otherwise mount entropy + checksum
    entropy_checksum = 0
    for word in words:
        # If nor valid quit
        if not word_is_valid(word):
            return False

        # Each word index has 11 bit, according to BIP39 definition
        entropy_checksum = entropy_checksum << 11 | WORDS_LIST_EN.index(word)

    print("Entropy + Chekcsum for verification: " + hex(entropy_checksum))

    # Get checksum from given sentence
    entropy_len = get_entropy_bit_length(number_of_words)
    checksum_len = get_checksum_length(entropy_len)
    mask = ~((0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) << checksum_len)
    given_checksum = entropy_checksum & mask
    print("Given checksum: " + hex(given_checksum))

    # Calculate checksum from given entropy
    entropy = entropy_checksum >> checksum_len
    calculated_checksum = get_entropy_checksum(entropy, int(entropy_len / 8))
    print("Calculated checksum: " + hex(calculated_checksum))

    # If given and calculated checksum are different, return False
    if given_checksum != calculated_checksum:
        return False

    # If all words are valid, return True
    return True

####################################################################################################

def sentence_to_seed(sentence, passphrase = ''):
    """
    Convert a sentence + optional passphrase to BIP39 seed.

    Parameters:
        sentence (str):     Sentence to be converted
        passphrase (str):   Optional passphrase to be used in conversion

    Return:
        Converted seed
    """

    # Verify sentence
    if not sentence_is_valid(sentence):
        raise ValueError("Invalid sentence")

    # BIP39 Definition:
    # The salt parameter to be used is the string 'mnemonic' appended to the passphrase.
    # If passphrase is empty, it is not a problem
    salt = 'mnemonic' + passphrase

    # BIP39 Definition:
    # The number of iteration id fixed 2048
    iteration_count = 2048

    # BIP39 Definition:
    # To generate the seed we have to use PBKDF2 function with:
    #  - HMAC-SHA512 as hash_name
    #  - sentence as password (all selected words blank space separated)
    #  - salt as string 'mnemonic' appended to the passphrase that could be empty
    #  - iteration count equal to 2048
    #  - both strings converted ro UTF-8 NFKD
    seed = hashlib.pbkdf2_hmac('sha512', sentence.encode('utf-8'), salt.encode('utf-8'),
                               iteration_count)

    return seed

####################################################################################################

def words_to_sentence(words_list):
    """
    Convert a list of words to a BIP39 sentence. Do not verify sentence validity, only the words.

    Parameters:
        words_list (list):  List of strings containing words to be converted in sentence

    Return:
        A space separated sentence containing given words
    """

    # The sentence is a string containing the ordered words space separated
    # So, iterate over all words creating a single string sentence
    sentence = ''
    for word in words_list:
        # Verify word
        if not word_is_valid(word):
            raise ValueError("Invalid word")

        sentence += word + ' '

    # At the end, strip sentence to remove trailing spaces
    sentence = sentence.strip()

    return sentence

####################################################################################################

def indexes_list_to_words_list(indexes_list):
    """
    Convert a list of indexes to a list of official English BIP39 words

    Parameters:
        indexes_list (list):    List of indexes to be converted do list of words

    Return:
        List of converted official English BIP39 words
    """

    words_list = []

    for i in indexes_list:
        words_list.append(WORDS_LIST_EN[i])

    return words_list

####################################################################################################

def get_entropy_bit_length(mnemonic_sentence_size = 12):
    """
    Get the entropy length in bits, given the mnemonic sentence length

    Parameters:
        mnemonic_sentence_size (int):   Number of words in mnemonic sentence

    Return:
        Number of bits to be used in entropy
    """

    # BIP39 Definition:
    # The following table describes the relation between the initial entropy length (ENT) and
    # mnemonic sentence (MS) in words.
    #
    # |  ENT  |  MS  |
    # +-------+------+
    # |  128  |  12  |
    # |  160  |  15  |
    # |  192  |  18  |
    # |  224  |  21  |
    # |  256  |  24  |

    # Get entropy bit size
    entropy_size = None
    if mnemonic_sentence_size == 12:
        entropy_size = 128
    elif mnemonic_sentence_size == 15:
        entropy_size = 160
    elif mnemonic_sentence_size == 18:
        entropy_size = 192
    elif mnemonic_sentence_size == 21:
        entropy_size = 224
    elif mnemonic_sentence_size == 24:
        entropy_size = 256
    else:
        raise ValueError("Invalid mnemonic_sentence_size of " + str(mnemonic_sentence_size))

    return entropy_size

####################################################################################################

def entropy_checksum_to_indexes_list(entropy_checksum, num_of_indexes):
    """
    Convert an entropy + checksum to list of indexes to be converted in words later

    Parameters:
        entropy_checksum (int): Entropy+checksum to be converted
        num_of_indexes (int):   Number of indexes to the entropy+checksum to be splited

    Return:
        List of indexes
    """

    # Create list with num_of_indexes elements filled with None
    indexes_list = [None for _ in range(num_of_indexes)]

    # Make a copy of entropy_checksum
    entropy_checksum_tmp = entropy_checksum

    for i in range(num_of_indexes):
        # BIP39 Definition:
        # Next, these concatenated bits are split into groups of 11 bits, each encoding a number
        # from 0-2047, serving as an index into a wordlist.

        # Get 11 LSb of entropy_checksum_tmp
        index = entropy_checksum_tmp & 0x7ff

        # The LS bits are the last index in the order, so we have to fill it backwards
        indexes_list[num_of_indexes - i - 1] = index

        # Clean out 11 LSb of entropy_checksum_tmp
        entropy_checksum_tmp = entropy_checksum_tmp >> 11

    return indexes_list

####################################################################################################

def get_checksum_length(entropy_len):
    """
    Calculate length in bits of checksum, given length in bits o entropy.

    Parameters:
        entropy_len (int):  Length of entropy in bits

    Return:
        Length of checksum in bits.
    """

    # BIP39 Definition:
    # Checksum length is entropy_len / 32
    return int(entropy_len / 32)

####################################################################################################

def get_entropy_checksum(entropy, entropy_len_bytes):
    """
    Calculate checksum of a given entropy.

    Parameters:
        entropy (int):              Entropy to calculate checksum
        entropy_len_bytes (int):    Length of entropy in bytes

    Return
        Calculated checksum.
    """

    # Get checksum to use it later
    entropy_len_bits = entropy_len_bytes * 8
    checksum_len = get_checksum_length(entropy_len_bits)

    # BIP39 Definition:
    # A checksum is generated by taking the first checksum_len bits (MSb) of its SHA256 hash.
    entropy_sha256 = hashlib.sha256(entropy.to_bytes(entropy_len_bytes, 'big')).digest()
    print("Entropy SHA256: 0x" + entropy_sha256.hex())
    shift = 256 - checksum_len # 256 is the number of bits in SHA256
    checksum = int.from_bytes(entropy_sha256, 'big') >> shift

    return checksum

####################################################################################################

def generate_sentence_from_entropy(entropy, mnemonic_sentence_size):
    """
    Generate a sentence using a given entropy and the on official BIP39 words.

    Parameters:
        entropy (int):                  Entropy to be used in sentence generation
        mnemonic_sentence_size (int):   Number of words in mnemonic sentence to be generated

    Return:
        Ordered list of official English BIP39 words based on given entropy
    """

    # Get entropy size according to mnemonic_sentence_size
    entropy_len = get_entropy_bit_length(mnemonic_sentence_size)
    entropy_len_bytes = int(entropy_len / 8)
    print("Entropy length in bits: " + str(entropy_len))

    # BIP39 Definition:
    # Checksum length is entropy_len / 32
    checksum_len = get_checksum_length(entropy_len)
    print("Checksum length in bits: " + str(checksum_len))

    # BIP39 Definition:
    # A checksum is generated by taking the first checksum_len bits (MSb) of its SHA256 hash.
    checksum = get_entropy_checksum(entropy, entropy_len_bytes)
    print("Checksum: " + hex(checksum))

    # BIP39 Definition:
    # This checksum is appended to the end (LSb side) of the initial entropy.
    entropy_checksum = (entropy << checksum_len) | checksum
    print("Entropy + Checksum: " + hex(entropy_checksum))

    # BIP39 Definition:
    # Next, these concatenated bits are split into groups of 11 bits, each encoding a number from
    # 0-2047, serving as an index into a wordlist.
    indexes_list = entropy_checksum_to_indexes_list(entropy_checksum, mnemonic_sentence_size)
    print("Indexes: " + str(indexes_list))

    # BIP39 Definition:
    # Finally, we convert these numbers into words and use the joined words as a mnemonic sentence.
    words_list = indexes_list_to_words_list(indexes_list)
    print("Words: " + str(words_list))

    print("Mnemonic Sentence: " + words_to_sentence(words_list))
    return words_list

####################################################################################################

def generate_random_sentence(mnemonic_sentence_size = 12):
    """
    Generate a random sentence.

    Parameters:
        mnemonic_sentence_size (int):   Number of words in mnemonic sentence to be generated

    Return:
        Ordered list of official English BIP39 words based on given entropy
    """
    # Get entropy size according to mnemonic_sentence_size
    entropy_len = get_entropy_bit_length(mnemonic_sentence_size)

    # Generate entropy
    entropy = secrets.randbits(entropy_len)
    print("Initial entropy: " + hex(entropy))

    return generate_sentence_from_entropy(entropy, mnemonic_sentence_size)


####################################################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Utility for BIP39.")
    parser.add_argument("-p", "--passphrase", type=str, default="", help="Passphrase to be used")
    parser.add_argument("-g", "--generate", type=int, choices=[12, 15, 18, 21, 24],
                        help="Passphrase to be used")
    args = parser.parse_args()

    load_wordlist()
    print("Seed: " + sentence_to_seed(words_to_sentence(generate_random_sentence(args.generate)),
                                             args.passphrase).hex())

from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from util import *


def encrypt(plaintext: str, key: str, counter_block: bytes) -> bytes:
    key = convert_to_bytes(key)
    plaintext = convert_to_bytes(plaintext)
    if len(plaintext) % 16 != 0:  # needs padding if not a multiple of 16
        plaintext = pad(plaintext, AES.block_size)

    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.encrypt(counter_block)

    # XOR the output with the plaintext
    ciphertext = xor_hex_strings(decode_byte_object(plaintext), decode_byte_object(output))
    ciphertext = convert_to_bytes(ciphertext)

    return ciphertext


def decrypt(bytes_ciphertext: bytes, key: str, counter_block: bytes) -> bytes:
    key = convert_to_bytes(key)

    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.encrypt(counter_block)

    # XOR the output with the plaintext
    plaintext = xor_hex_strings(decode_byte_object(bytes_ciphertext), decode_byte_object(output))
    plaintext = convert_to_bytes(plaintext)

    return plaintext


def encrypt_ctr(msg: str, key: str, nonce: str, counter_start: str) -> bytes:
    # convert the input plaintext into byte object
    byte_msg = convert_to_bytes(msg)
    # split the plaintext into 16 byte chunks (each index is byte object representation of plaintext)
    split_msg = split_into_chunks(byte_msg)
    # create new array with same size as split
    encrypt_msg = [0] * len(split_msg)
    nonce = convert_to_bytes(nonce)
    counter_start = convert_to_bytes(counter_start)
    counter_block = combine_bytes(nonce, counter_start)
    # counter_block = convert_to_bytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    feedback = ""
    for index, plaintext in enumerate(split_msg):
        encrypt_msg[index] = encrypt(decode_byte_object(plaintext), key, counter_block)
        # recreate the counter block with fixed nonce and updated counter
        counter_block = increment_bytes(counter_block)
        # counter_block = combine_bytes(nonce, counter_start)
    return concatenate_byte_objects(encrypt_msg)


def decrypt_ctr(byte_msg: bytes, key: str, nonce: str, counter_start: str) -> bytes:
    # split ciphertext into 16 byte chunks
    split_msg = split_into_chunks(byte_msg)
    # create list with same size as split_msg
    decrypt_msg = [0] * len(split_msg)
    nonce = convert_to_bytes(nonce)
    counter_start = convert_to_bytes(counter_start)
    counter_block = combine_bytes(nonce, counter_start)
    # counter_block = convert_to_bytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    feedback = ""
    for index, ciphertext in enumerate(split_msg):
        decrypt_msg[index] = decrypt(ciphertext, key, counter_block)
        # recreate the counter block with fixed nonce and updated counter
        # counter_block = increment_bytes(counter_block)
        counter_start = increment_bytes(counter_start)
        counter_block = combine_bytes(nonce, counter_start)

    """The last element in decrypt_msg needs to be checked for padding
    It is the only element that could have padding as well. This is due to the message
    being split into 16 byte chunks before being encrypted. This means only the last (or
    possibly the first chunk if the size is <= 16 bytes) chunk needs to be unpadded"""
    try:
        unpad_plaintext = unpad(decrypt_msg[-1], AES.block_size)
        decrypt_msg[-1] = unpad_plaintext
    except ValueError:  # unpad will throw an error if the plaintext was not padded to begin with
        pass

    return concatenate_byte_objects(decrypt_msg)


def test_ctr():
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    nonce = 'f78a0908c9083734'
    counter = '0000000000000000'
    msg = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'
    print('\nMulti-block message test from AES Standard.  '
          f"\nInput to Program: \nKey = {key}"
          f" | Nonce = {nonce}"
          f" | Counter = {counter}"
          f"\nPlaintext =       {group_string(msg)}"
          '\nExpected Cipher:  4a22cfef8843bb96e1ddfe8b1960472a 7930b7193726abf52480fdb058653367 d2ff5e93611574ac6997de2c8f5e6d1d 4b251767ac762e72a8552da6068c5894')
    ct = (encrypt_ctr(msg, key, nonce, counter))

    # # this section here is the same as the code example seen in the document
    # # if you uncomment out these 3 lines of code, you can see how the bit flip affects the cipher
    # split = split_into_chunks(ct)
    # # this line of code causes an "error" in the ciphertext by flipping one of the bits.
    # split[1] = flip_bit((split[1]))
    # ct = concatenate_byte_objects(split)
    print('Cipher:          ', group_string(ct.hex()))
    print('Decrypted Cipher:', group_string(decode_byte_object(decrypt_ctr(ct, key, nonce, counter))))

    key2 = '00000000000000000000000000000000'
    nonce2 = 'f78a0908c9083734'
    counter2 = '0000000000000000'
    msg2 = 'Normal text'
    print('\nCTR test with ASCII printable characters (not hex) '
          f"\nInput to Program: \nKey = {key2}"
          f" | Nonce = {nonce2}"
          f" | Counter = {counter}"
          f" | Plaintext = \"{msg2}\"")
    ct2 = (encrypt_ctr(msg2, key2, nonce2, counter2))
    print('Cipher:', group_string(ct2.hex()))
    print('Decrypted Cipher:', decode_byte_object(decrypt_ctr(ct2, key2, nonce2, counter2)))

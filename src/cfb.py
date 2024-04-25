from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from util import *


def encrypt(plaintext: str, key: str, input_block: bytes, segment_size: int) -> bytes:
    key = convert_to_bytes(key)
    plaintext = convert_to_bytes(plaintext)
    segment_bytes = segment_size // 8

    if len(plaintext) < segment_bytes:  # pad plaintext if its less than the segment size in bytes
        plaintext = pad(plaintext, segment_bytes)

    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.encrypt(input_block)

    # select s bits
    select_mask = gen_mask(segment_size)
    # take the s most significant bits from the output block
    s_bits = select_mask & int.from_bytes(output, byteorder='big')
    s_bits = s_bits.to_bytes(16, byteorder='big')
    # move s_bits to least significant side.
    s_bits = bitwise_shift(s_bits, 128 - segment_size, False)

    # XOR the plaintext s bits with the s bits from the output
    ciphertext = xor_hex_strings(decode_byte_object(s_bits), decode_byte_object(plaintext))
    ciphertext = convert_to_bytes(ciphertext)
    # truncate ciphertext from 16 bytes to the size of the segment
    # so if segment is 32, ciphertext becomes 4 bytes long
    ciphertext = int.from_bytes(ciphertext, byteorder='big')
    ciphertext = ciphertext.to_bytes(segment_bytes, byteorder='big')

    return ciphertext


def decrypt(bytes_ciphertext: bytes, key: str, input_block: bytes, segment_size: int) -> bytes:
    key = convert_to_bytes(key)
    segment_bytes = segment_size // 8

    cipher = AES.new(key, AES.MODE_ECB)
    output = cipher.encrypt(input_block)

    # select s bits
    select_mask = gen_mask(segment_size)
    # take the s most significant bits from the output block
    s_bits = select_mask & int.from_bytes(output, byteorder='big')
    s_bits = s_bits.to_bytes(16, byteorder='big')
    # move s_bits to least significant side.
    s_bits = bitwise_shift(s_bits, 128 - segment_size, False)

    # XOR the ciphertext s bits with the s bits from the output
    plaintext = xor_hex_strings(decode_byte_object(s_bits), decode_byte_object(bytes_ciphertext))
    plaintext = convert_to_bytes(plaintext)
    # truncate ciphertext from 16 bytes to the size of the segment
    # so if segment is 32, ciphertext becomes 4 bytes long
    plaintext = int.from_bytes(plaintext, byteorder='big')
    plaintext = plaintext.to_bytes(segment_bytes, byteorder='big')

    return plaintext


def encrypt_cfb(msg: str, key: str, iv: str, segment_size: int) -> bytes:
    if segment_size < 0 or segment_size > 128 or not segment_size % 8 == 0:
        raise ValueError("Segment size must be positive, a multiple of 8 bits, and no greater than 128 bits.")
    # convert the input plaintext into byte object
    byte_msg = convert_to_bytes(msg)
    # split the plaintext into (segment_size // 8) byte chunks (each index is byte object representation of plaintext)
    # for example: segment_size of 8 means each plaintext segment will be 1 byte or 8 bits
    split_msg = split_into_chunks(byte_msg, segment_size // 8)
    # create new array with same size as split
    encrypt_msg = [0] * len(split_msg)
    iv = convert_to_bytes(iv)
    # if segment_size is 128, the iv will become all 0's
    shifted_iv = bitwise_shift(iv, segment_size, True)
    for index, plaintext in enumerate(split_msg):
        if index == 0:
            encrypt_msg[index] = encrypt(decode_byte_object(plaintext), key, iv, segment_size)
        else:
            feedback = or_hex_strings(decode_byte_object(shifted_iv), decode_byte_object(encrypt_msg[index - 1]))
            encrypt_msg[index] = encrypt(decode_byte_object(plaintext), key, convert_to_bytes(feedback), segment_size)
            shifted_iv = bitwise_shift(convert_to_bytes(feedback), segment_size, True)

    return concatenate_byte_objects(encrypt_msg)


def decrypt_cfb(byte_msg: bytes, key: str, iv: str, segment_size: int) -> bytes:
    if segment_size < 0 or segment_size > 128 or not segment_size % 8 == 0:
        raise ValueError("Segment size must be positive, a multiple of 8 bits, and no greater than 128 bits.")
    # split the ciphertext into (segment_size // 8) byte chunks (each index is byte object representation of plaintext)
    # for example: segment_size of 8 means each plaintext segment will be 1 byte or 8 bits
    split_msg = split_into_chunks(byte_msg, segment_size // 8)
    # create list with same size as split_msg
    decrypt_msg = [0] * len(split_msg)
    feedback = ""
    iv = convert_to_bytes(iv)
    # if segment_size is 128, the iv will become all 0's
    shifted_iv = bitwise_shift(iv, segment_size, True)
    for index, ciphertext in enumerate(split_msg):
        if index == 0:
            decrypt_msg[index] = decrypt(ciphertext, key, iv, segment_size)
        else:
            prev_ciphertext = split_msg[index - 1]
            feedback = or_hex_strings(decode_byte_object(shifted_iv), decode_byte_object(prev_ciphertext))
            decrypt_msg[index] = decrypt(ciphertext, key, convert_to_bytes(feedback), segment_size)
            shifted_iv = bitwise_shift(convert_to_bytes(feedback), segment_size, True)

    """The last element in decrypt_msg needs to be checked for padding
    It is the only element that could have padding as well. This is due to the message
    being split into (segment_size // 8) byte chunks before being encrypted. This means only the last (or
    possibly the first chunk if the size is <= 16 bytes) chunk needs to be unpadded"""
    try:
        unpad_plaintext = unpad(decrypt_msg[-1], segment_size // 8)
        decrypt_msg[-1] = unpad_plaintext
    except ValueError:  # unpad will throw an error if the plaintext was not padded to begin with
        pass

    return concatenate_byte_objects(decrypt_msg)


def test_cfb():
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    iv = '000102030405060708090a0b0c0d0e0f'
    msg = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'
    print('\nCFB Multi-block message test from AES Standard.  '
          f"\nInput to Program: \nKey = {key}"
          f" | IV = {iv}"
          f"\nPlaintext =       {group_string(msg)}"
          '\nExpected Cipher:  3b3fd92eb72dad20333449f8e83cfb4a c8a64537a0b3a93fcde3cdad9f1ce58b 26751f67a3cbb140b1808cf187a4f4df c04b05357c5d1c0eeac4c66f9ff7f2e6')
    ct = (encrypt_cfb(msg, key, iv, 128))

    # # this section here is the same as the code example seen in the document
    # # if you uncomment out these 3 lines of code, you can see how the bit flip affects the cipher
    # split = split_into_chunks(ct)
    # # this line of code causes an "error" in the ciphertext by flipping one of the bits.
    # split[1] = flip_bit((split[1]))
    # ct = concatenate_byte_objects(split)

    print('Cipher:          ', (group_string(ct.hex())))
    print('Decrypted Cipher:', group_string(decode_byte_object(decrypt_cfb(ct, key, iv, 128))))

    key2 = '00000000000000000000000000000000'
    iv2 = '00000000000000000000000000000000'
    msg2 = 'Normal text'
    print('\nCFB test with ASCII printable characters (not hex) '
          f"\nInput to Program: \nKey = {key}"
          f" | IV = {iv}"
          f" | Plaintext = \"{msg2}\"")
    ct2 = (encrypt_cfb(msg2, key2, iv2, 64))
    print('Cipher:', group_string(ct2.hex()))
    print('Decrypted Cipher:', decode_byte_object(decrypt_cfb(ct2, key2, iv2, 64)))

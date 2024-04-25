from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from util import *


def encrypt(plaintext: str, key: str, iv: str) -> tuple[bytes, bytes]:
    iv = convert_to_bytes(iv)
    key = convert_to_bytes(key)
    plaintext = convert_to_bytes(plaintext)
    if len(plaintext) % 16 != 0:  # needs padding if not a multiple of 16
        plaintext = pad(plaintext, AES.block_size)

    cipher = AES.new(key, AES.MODE_ECB)
    feedback = cipher.encrypt(iv)

    # XOR the feedback with the plaintext
    ciphertext = xor_hex_strings(decode_byte_object(plaintext), decode_byte_object(feedback))
    ciphertext = convert_to_bytes(ciphertext)

    return ciphertext, feedback


def decrypt(bytes_ciphertext: bytes, key: str, iv: str) -> tuple[bytes, bytes]:
    iv = convert_to_bytes(iv)
    key = convert_to_bytes(key)

    cipher = AES.new(key, AES.MODE_ECB)
    # OFB mode encrypts again (unlike CBC which decrypts in this step)
    feedback = cipher.encrypt(iv)

    # XOR the feedback with the ciphertext
    plaintext = xor_hex_strings(decode_byte_object(bytes_ciphertext), decode_byte_object(feedback))
    plaintext = convert_to_bytes(plaintext)

    return plaintext, feedback


def encrypt_ofb(msg: str, key: str, iv: str) -> bytes:
    # convert the input plaintext into byte object
    byte_msg = convert_to_bytes(msg)
    # split the plaintext into 16 byte chunks (each index is byte object representation of plaintext)
    split_msg = split_into_chunks(byte_msg)
    # create new array with same size as split
    encrypt_msg = [0] * len(split_msg)
    feedback = ""
    for index, plaintext in enumerate(split_msg):
        if index == 0:  # first index we encrypt the IV
            encrypt_msg[index], feedback = encrypt(decode_byte_object(plaintext), key, iv)
        else:  # subsequent encryption uses feedback instead of iv
            encrypt_msg[index], feedback = encrypt(decode_byte_object(plaintext), key, decode_byte_object(feedback))
    return concatenate_byte_objects(encrypt_msg)


def decrypt_ofb(byte_msg: bytes, key: str, iv: str) -> bytes:
    # split ciphertext into 16 byte chunks
    split_msg = split_into_chunks(byte_msg)
    # create list with same size as split_msg
    decrypt_msg = [0] * len(split_msg)
    feedback = ""
    for index, ciphertext in enumerate(split_msg):
        if index == 0:  # first block encrypts with IV
            decrypt_msg[index], feedback = decrypt(ciphertext, key, iv)
        else:  # subsequent plaintext use previous ciphertext as IV
            decrypt_msg[index], feedback = decrypt(ciphertext, key, decode_byte_object(feedback))

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


def test_ofb():
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    iv = '000102030405060708090a0b0c0d0e0f'
    msg = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'
    print('\nOFB Multi-block message test from AES Standard.  '
          f"\nInput to Program: \nKey = {key}"
          f" | IV = {iv}"
          f"\nPlaintext =       {group_string(msg)}"
          '\nExpected Cipher:  3b3fd92eb72dad20333449f8e83cfb4a 7789508d16918f03f53c52dac54ed825 9740051e9c5fecf64344f7a82260edcc 304c6528f659c77866a510d9c1d6ae5e')
    ct = (encrypt_ofb(msg, key, iv))

    # # this section here is the same as the code example seen in the document
    # # if you uncomment out these 3 lines of code, you can see how the bit flip affects the cipher
    # split = split_into_chunks(ct)
    # # this line of code causes an "error" in the ciphertext by flipping one of the bits.
    # split[1] = flip_bit((split[1]))
    # ct = concatenate_byte_objects(split)

    print('Cipher:          ', group_string(ct.hex()))
    print('Decrypted Cipher:', group_string(decode_byte_object(decrypt_ofb(ct, key, iv))))

    key2 = '00000000000000000000000000000000'
    iv2 = '00000000000000000000000000000000'
    msg2 = 'Normal text'
    print('\nOFB test with ASCII printable characters (not hex) '
          f"\nInput to Program: \nKey = {key2}"
          f" | IV = {iv2}"
          f" | Plaintext = \"{msg2}\"")
    ct2 = (encrypt_ofb(msg2, key2, iv2))
    print('Cipher:', group_string(ct2.hex()))
    print('Decrypted Cipher:', decode_byte_object(decrypt_ofb(ct2, key2, iv2)))

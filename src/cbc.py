from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from util import *


def encrypt(plaintext: str, key: str, iv: str) -> bytes:
    plaintext = convert_to_bytes(plaintext)
    key = convert_to_bytes(key)
    iv = convert_to_bytes(iv)
    if len(plaintext) % 16 != 0:  # needs padding if not a multiple of 16
        plaintext = pad(plaintext, AES.block_size)
    # XOR the plaintext with the IV
    new_plaintext = xor_hex_strings(decode_byte_object(plaintext), decode_byte_object(iv))
    new_plaintext = convert_to_bytes(new_plaintext)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(new_plaintext)

    return ciphertext


def decrypt(bytes_ciphertext: bytes, key: str, iv: str) -> bytes:
    key = convert_to_bytes(key)
    iv = convert_to_bytes(iv)
    cipher = AES.new(key, AES.MODE_ECB)
    bytes_plaintext = cipher.decrypt(bytes_ciphertext)
    # XOR the decrypted ciphertext to get back the original plaintext
    new_bytes_plaintext = xor_hex_strings(decode_byte_object(bytes_plaintext), decode_byte_object(iv))
    new_bytes_plaintext = convert_to_bytes(new_bytes_plaintext)

    return new_bytes_plaintext


def encrypt_cbc(msg: str, key: str, iv: str) -> bytes:
    # convert the input plaintext into byte object
    byte_msg = convert_to_bytes(msg)
    # split the plaintext into 16 byte chunks (each index is byte object representation of plaintext)
    split_msg = split_into_chunks(byte_msg)
    # create new array with same size as split
    encrypt_msg = [0] * len(split_msg)
    for index, plaintext in enumerate(split_msg):
        if index == 0:  # first plaintext gets XOR with the IV
            encrypt_msg[index] = encrypt(decode_byte_object(plaintext), key, iv)
        else:  # subsequent plaintext use previous ciphertext as IV
            iv = decode_byte_object(encrypt_msg[index - 1])
            encrypt_msg[index] = encrypt(decode_byte_object(plaintext), key, iv)

    return concatenate_byte_objects(encrypt_msg)


def decrypt_cbc(byte_msg: bytes, key: str, iv: str) -> bytes:
    # split ciphertext into 16 byte chunks (each index is byte object representation of ciphertext)
    split_msg = split_into_chunks(byte_msg)
    # create list with same size as split_msg
    decrypt_msg = [0] * len(split_msg)
    for index, ciphertext in enumerate(split_msg):
        if index == 0:  # first plaintext gets XOR with the IV
            decrypt_msg[index] = decrypt(ciphertext, key, iv)
        else:  # subsequent plaintext use previous ciphertext as IV
            iv = decode_byte_object(split_msg[index - 1])
            decrypt_msg[index] = decrypt(ciphertext, key, iv)

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


def test_cbc():
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    iv = '000102030405060708090a0b0c0d0e0f'
    msg = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'
    print('\nCBC Multi-block message test from AES Standard.'
          f"\nInput to Program: \nKey = {key}"
          f" | IV = {iv}"
          f"\nPlaintext =       {group_string(msg)}"
          '\nExpected Cipher:  7649abac8119b246cee98e9b12e9197d 5086cb9b507219ee95db113a917678b2 73bed6b8e3c1743b7116e69e22229516 3ff1caa1681fac09120eca307586e1a7')
    ct = (encrypt_cbc(msg, key, iv))

    # this section here is the same as the code example seen in the document
    # if you uncomment out these 3 lines of code, you can see how the bit flip affects the cipher
    split = split_into_chunks(ct)
    # this line of code causes an "error" in the ciphertext by flipping one of the bits.
    split[1] = flip_bit((split[1]))
    ct = concatenate_byte_objects(split)

    print('Cipher:          ', group_string(ct.hex()))
    print('Decrypted Cipher:', group_string(decode_byte_object(decrypt_cbc(ct, key, iv))))

    key2 = '00000000000000000000000000000000'
    iv2 = '00000000000000000000000000000000'
    msg2 = 'Normal text'
    print('\nCBC test with ASCII printable characters (not hex) '
          f"\nInput to Program: \nKey = {key2}"
          f" | IV = {iv2}"
          f" | Plaintext = \"{msg2}\"")
    ct2 = (encrypt_cbc(msg2, key2, iv2))
    print('Cipher:', group_string(ct2.hex()))
    print('Decrypted Cipher:', decode_byte_object(decrypt_cbc(ct2, key2, iv2)))


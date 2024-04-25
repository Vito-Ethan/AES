from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from util import *


def encrypt_ecb(plaintext: str, key: str) -> bytes:
    plaintext = convert_to_bytes(plaintext)
    key = convert_to_bytes(key)

    if len(plaintext) % 16 != 0:  # needs padding if not a multiple of 16
        plaintext = pad(plaintext, AES.block_size)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def decrypt_ecb(ciphertext: bytes, key: str) -> bytes:
    key = convert_to_bytes(key)
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)

    try:
        plaintext = unpad(plaintext, AES.block_size)
    except ValueError:  # unpad will throw an error if the plaintext was not padded to begin with
        pass

    return plaintext


def group_string(s: str) -> str:
    return ' '.join([s[i:i + 32] for i in range(0, len(s), 32)])


def test_ecb():
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    msg = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'
    print('ECB Multi-block message test from AES Standard. '
          f"\nInput to Program: \nKEY = {key}"
          f" | IV = None for ECB"
          f"\nPlaintext =       {group_string(msg)}"
          '\nExpected Cipher:  3ad77bb40d7a3660a89ecaf32466ef97 f5d3d58503b9699de785895a96fdbaaf 43b1cd7f598ece23881b00e3ed030688 7b0c785e27e8ad3f8223207104725dd4')
    ct = (encrypt_ecb(msg, key))

    # # this section here is the same as the code example seen in the document
    # # if you uncomment out these 3 lines of code, you can see how the bit flip affects the cipher
    # split = split_into_chunks(ct)
    # # this line of code causes an "error" in the ciphertext by flipping one of the bits.
    # split[1] = flip_bit((split[1]))
    # ct = concatenate_byte_objects(split)

    print('Cipher:          ', group_string(ct.hex()))
    print('Decrypted Cipher:', group_string(decode_byte_object(decrypt_ecb(ct, key))))

    key2 = '00000000000000000000000000000000'
    msg2 = 'Normal text'
    print('\nECB test with ASCII printable characters (not hex) '
          f"\nInput to Program: \nKey = {key2}"
          f" | IV = None for ECB"
          f"\nPlaintext = \"{msg2}\"")
    ct2 = (encrypt_ecb(msg2, key2))
    print('Cipher:', group_string(ct2.hex()))
    print('Decrypted Cipher:', decode_byte_object(decrypt_ecb(ct2, key2)))
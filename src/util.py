import math
from typing import List
import secrets

def is_hex(s: str) -> bool:
    """Check if string represents hex value"""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def convert_to_bytes(s: str) -> bytes:
    """Converts a string into a byte object"""
    if len(s) != 1 and is_hex(s):  # If string length is 1, it cannot be a hex value so don't check. Convert hex val to bytes
        bytes_string = bytes.fromhex(s)
    else:  # convert non-hex string into a byte obj
        hex_string = s.encode("utf-8").hex()
        bytes_string = bytes.fromhex(hex_string)
    return bytes_string


def decode_byte_object(byte_obj: bytes) -> str:
    """Converts a byte object into a string"""
    try:
        # try to decode as UTF-8 (assuming it's a regular string)
        decoded_str = byte_obj.decode('utf-8')

        # check if the decoded string contains only printable ASCII characters
        if all(32 <= ord(char) < 127 for char in decoded_str):
            return decoded_str
    except UnicodeDecodeError:
        pass

    # if decoding as UTF-8 fails or if the string is not printable ASCII, assume it's a hex value
    hex_str = byte_obj.hex()
    return hex_str


def xor_hex_strings(hex_str1: str, hex_str2: str) -> str:
    """Perform a bitwise XOR for two hex strings"""
    # convert strings to bytes
    bytes1 = convert_to_bytes(hex_str1)
    bytes2 = convert_to_bytes(hex_str2)

    diff = 16 - len(bytes2)
    if diff != 0:
        padding = b'\x00' * diff
        bytes2 = padding + bytes2

    # XOR each corresponding pair of bytes
    result_bytes = bytes(x ^ y for x, y in zip(bytes1, bytes2))

    # convert the result back to a hex string
    result_hex = result_bytes.hex()

    return result_hex


def or_hex_strings(hex_str1: str, hex_str2: str) -> str:
    """Performs a bitwise OR for two hex strings"""
    # convert strings to bytes
    bytes1 = convert_to_bytes(hex_str1)
    bytes2 = convert_to_bytes(hex_str2)

    # add padding to make sure the second hex string is 16 bytes
    # otherwise the zip function will only iterate as many times as min(hex_str1, hex_str2)
    diff = 16 - len(bytes2)
    if diff != 0:
        padding = b'\x00' * diff
        bytes2 = padding + bytes2

    # OR each corresponding pair of bytes
    result_bytes = bytes(x | y for x, y in zip(bytes1, bytes2))

    # convert the result back to a hex string
    result_hex = result_bytes.hex()

    return result_hex


def split_into_chunks(byte_obj: bytes, chunk_size: int = 16) -> List[bytes]:
    """Splits byte object into an array of equally sized byte objects. By default, this is
    splitting into 16 byte objects. Used to split user input into an array of bytes."""
    num_chunks = (len(byte_obj) + chunk_size - 1) // chunk_size
    # num_chunks = math.ceil(len(byte_obj) / CHUNK_SIZE)

    chunks = [byte_obj[i * chunk_size:(i + 1) * chunk_size] for i in range(num_chunks)]

    return chunks


def concatenate_byte_objects(byte_obj: List[bytes]) -> bytes:
    """Turns a list of bytes into one byte object"""
    concatenated_bytes = b''.join(byte_obj)
    return concatenated_bytes


def group_string(s: str) -> str:
    """Formats a string so it is separated by every 16 bytes"""
    return ' '.join([s[i:i + 32] for i in range(0, len(s), 32)])


def combine_bytes(byte_obj1: bytes, byte_obj2: bytes) -> bytes:
    """Combines two byte objects. In this case, combines two 64 bit byte objects to make one 128 bit byte object"""
    # check if objects are 64 bits (8 bytes) long
    if len(byte_obj1) != 8 or len(byte_obj2) != 8:
        raise ValueError("Both input byte objects must be 64 bits (8 bytes) long.")

    combined_bytes = bytes(byte_obj1 + byte_obj2)

    return combined_bytes


def increment_bytes(byte_obj: bytes) -> bytes:
    """Increments the value of a bytes object by 1"""
    int_val = int.from_bytes(byte_obj, byteorder='big')
    incremented_val = int_val + 1
    incremented_byte_obj = incremented_val.to_bytes(len(byte_obj), byteorder='big')

    return incremented_byte_obj


def bitwise_shift(byte_obj: bytes, shift_amount: int, isleft: bool) -> bytes:
    """Perform a bitwise left shift if isleft is true or a bitwise right shift if isleft is false.
    Shifts by the designated shift_amount."""
    CHUNK_SIZE = 16
    # 128 bit mask of 1's
    mask = (1 << (CHUNK_SIZE * 8)) - 1

    int_val = int.from_bytes(byte_obj, byteorder='big')

    shifted_val = int_val << shift_amount if isleft else int_val >> shift_amount

    # bitwise AND the new value with a mask of 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    # this ensures we only keep 128 bits since python integers are arbitrary
    shifted_val &= mask
    # Convert back to bytes with the specified length
    shifted_bytes = shifted_val.to_bytes(CHUNK_SIZE, byteorder='big')

    return shifted_bytes


def bytes_to_binary_string(bytes_obj):
    """Will convert a bytes object to its binary string representation"""
    # [2:] strips the leading 0b
    binary_string = bin(int.from_bytes(bytes_obj, byteorder='big'))[2:]
    BLOCK_SIZE = 8 * len(bytes_obj)

    return binary_string.zfill(BLOCK_SIZE)


def gen_mask(segment_size: int) -> int:
    """Will generate a 128-bit mask with as many 1's as the segment_size.
    For example, if segment_size = 4, we will get a 128-bit number with
    the 4 most significant bits set to 1 (0b1111...)"""
    if not (0 <= segment_size <= 128):
        raise ValueError("Invalid number of bits to keep")

    # generate a mask of 1's with size of s-bits
    mask = (1 << segment_size) - 1

    # shift the mask to left most side of 128-bit number
    mask = mask << (128 - segment_size)
    # mask = mask.to_bytes(16, byteorder='big')

    return mask


def gen_key() -> str:
    """generates a random 128bit key"""
    random_key = secrets.token_hex(16)

    return random_key


def flip_bit(byte_obj: bytes) -> bytes:
    """Flips the LSB of the given hex string"""
    int_obj = int.from_bytes(byte_obj, byteorder='big')

    # flip the LSB by XOR with a 1
    int_obj ^= 1

    byte_obj = int_obj.to_bytes(len(byte_obj), byteorder='big')

    return byte_obj
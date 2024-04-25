from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from util import convert_to_bytes


def gen_key_pair():
    # generate key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("public.pem", "wb")
    file_out.write(public_key)
    file_out.close()


def test_rsa():
    data = convert_to_bytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710')
    recipient_publickey = RSA.importKey(open('public.pem').read())
    session_key = get_random_bytes(16)

    # encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_publickey)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # encrypt the data with AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    # get the ciphertext and also a MAC tag to verify the file
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    nonce = cipher_aes.nonce


    private_key = RSA.importKey(open('private.pem').read())
    # decrypt session key with the private RSA key
    cipher_rsa2 = PKCS1_OAEP.new(private_key)
    session_key2 = cipher_rsa2.decrypt(enc_session_key)

    # decrypt the data with AES session key
    cipher_aes2 = AES.new(session_key2, AES.MODE_EAX, nonce)
    data_decode = cipher_aes2.decrypt_and_verify(ciphertext, tag)

    # print(data_decode.decode("utf-8"))


def test_eax():
    key = convert_to_bytes('2b7e151628aed2a6abf7158809cf4f3c')
    msg = convert_to_bytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    nonce = cipher.nonce

    d_cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = d_cipher.decrypt_and_verify(ciphertext, tag)
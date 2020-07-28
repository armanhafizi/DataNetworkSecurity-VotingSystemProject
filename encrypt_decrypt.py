from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

def rsa_encrypt(pubKey, msg):
    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(msg)
    return encrypted

def rsa_decrypt(privKey, msg_enc):
    decryptor = PKCS1_OAEP.new(privKey)
    decrypted = decryptor.decrypt(msg_enc)
    return decrypted

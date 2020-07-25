from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

def rsa_encrypt(pu_key_path, msg):
    pubKey = RSA.importKey(open(pu_key_path, "rb").read())
    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(msg)
    return encrypted

def rsa_decrypt(pr_key_path, msg_enc):
    privKey = RSA.importKey(open(pr_key_path, "rb").read())
    decryptor = PKCS1_OAEP.new(privKey)
    decrypted = decryptor.decrypt(msg_enc)
    return decrypted

# print(rsa_encrypt(key_path, msg))
print(rsa_decrypt("PR_CA.key", rsa_encrypt("PU_CA.key", b"hello bitch")))

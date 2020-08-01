import json, string, random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode
from encrypt_decrypt import rsa_encrypt, rsa_decrypt
from datetime import datetime, timedelta
import rsa
def verify_sign(PU_loc, signature, data):
    PU = open(PU_loc, 'r').read()
    rsakey = RSA.importKey(PU)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(data)
    if signer.verify(digest, b64decode(signature)):
        return True
    else:
        return False

def sign_data(PR_loc, data):
    PR = open(PR_loc, 'r').read()
    rsakey = RSA.importKey(PR)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(data)
    sign = signer.sign(digest)
    return b64encode(sign)
def main():
    if True:
        x = 2
    print(x)
if __name__== "__main__":
    main()
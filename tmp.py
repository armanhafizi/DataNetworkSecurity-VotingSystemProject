import json, string
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode
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
    data = {'id':2, 'x':'lwA9fQKqpEmmxrMUGYK7VzCbojmpF9FtOJPXa1QKwLSXblbVrZXtKGVybPmuqRl8Y+jMhtdq9zMlQv5PDai325H44oa7OwpWnVrDehKq4DPDpXhuUjyGqvKdvz45P8y2L5tc+jvvzLi3t6D7m2oVPoJ+qb8aVWBFKDj0y112hpM='}
    d = json.dumps(data)
    e = json.loads(d)
    print(d)

if __name__== "__main__":
    main()
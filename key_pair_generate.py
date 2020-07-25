from Crypto.PublicKey import RSA 
from Crypto import Random
import ast

from Crypto.PublicKey import RSA


def generate_keys():
    modulus_length = 1024
    key = RSA.generate(modulus_length)
    pub_key = key.publickey()
    private_key = key.exportKey()
    f = open("PR_CA.key", "wb").write(private_key)
    public_key = pub_key.exportKey()
    f = open("PU_CA.key", "wb").write(public_key)
    return private_key, public_key


k = generate_keys()
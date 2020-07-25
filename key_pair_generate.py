from OpenSSL import crypto, SSL
from Crypto.PublicKey import RSA 
from Crypto import Random
import ast

def gen_rsa_key_pair():
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)
    open("PU_CA.key", "wb").write(crypto.dump_publickey(crypto.FILETYPE_PEM, k))
    open("PR_CA.key", "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

def crypto_key_pair():
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    pu_ca = key.publicKey()
    encrypted = pu_ca.encrypt('message sad as', 32)
    print(encrypted)

crypto_key_pair()
# gen_rsa_key_pair()
pr_file = open('PR_CA.key', 'rb').read()
PR_CA = crypto.load_privatekey(crypto.FILETYPE_PEM, pr_file)
print(PR_CA)
import socket, json, threading, binascii, random, string, codecs
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from encrypt_decrypt import rsa_encrypt, rsa_decrypt
from sha_hash import sha_hash
from symmetric_enc_dec import symmetric_encrypt, symmetric_decrypt
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode

class Client:
    HOST = "127.0.0.1"
    state = 0

    def __init__(self, id, name):
        self.ID = id
        self.NAME = name
        self.PU_CA = RSA.importKey(open("PU_CA.key", "rb").read())

    def connect(self, port, name):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.HOST, port))
            while True:
                if (self.state == 0 and name == "CA"):
                    # encrypt hash of message
                    M = self.ID + self.NAME
                    K_C = self.ID + 'S3'
                    signature = symmetric_encrypt(K_C, sha_hash(bytes(M, encoding="utf-8")))
                    # final message
                    msg = {"ID": self.ID, "NAME": self.NAME, "TS1": 1, "LT1": 10, "signature": signature.decode("utf-8")}
                    # encrypt key
                    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 5))
                    PU_CA = RSA.importKey(open('PU_CA.key', "rb").read())
                    key_enc = rsa_encrypt(PU_CA, bytes(key, encoding="utf-8"))
                    # encrypt message
                    msg_enc = symmetric_encrypt(key, json.dumps(msg))
                    data = json.dumps({"message": msg_enc.decode("utf-8"), "key": key_enc.hex()})
                    # send message
                    s.sendall(bytes(data, encoding="utf-8"))
                    # next state
                    self.state = 1
                if (self.state == 1 and name == "CA"):
                    # receive
                    data = s.recv(4096)
                    # decrypt message
                    K_C = self.ID + 'S3'
                    data = json.loads(symmetric_decrypt(K_C, data))
                    # extract data
                    self.PU_AS = data["PU_AS"]
                    self.PR_C = data["PR_C"]
                    self.PU_C = data["PU_C"]
                    self.cert_encrypted = data["cert_encrypted"]
                    ts = data["TS2"]
                    lt = data["LT2"]
                    signature = data["signature"]
                    # JUST‌ TO CHECK !!! decrpyt certificaion
                    certification = {"ID": self.ID, "PU_C": self.PU_C}
                    certification = bytes(json.dumps(certification), encoding = 'utf-8')
                    PU_CA = RSA.importKey(open('PU_CA.key', "rb").read())
                    status = self.verify_sign(PU_CA, self.cert_encrypted, certification)
                    print('certification:'+str(status))
                    #TODO check TS and LT
                    # check hash
                    if sha_hash(bytes(self.PU_AS + self.PR_C + self.cert_encrypted, encoding="utf-8")) == signature:
                        print("Correct Signature")
                        # next state
                        self.state = 2
                    else:
                        print("Incorrect Signature")
                        # previous state
                        self.state = 0
                if (self.state == 2 and name == "AS"):
                    # sign hash of message
                    M = self.ID + self.cert_encrypted
                    signature = self.sign_data(RSA.importKey(self.PR_C) , bytes(sha_hash(bytes(M, encoding="utf-8")),encoding="utf-8"))
                    signature = signature.decode('utf-8')
                    # final message
                    msg = {"ID": self.ID,'PU_C': self.PU_C, "cert_encrypted": self.cert_encrypted, "TS3": 1, "LT3": 10, 'signature': signature}
                    # encrypt key
                    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 5))
                    key_enc = rsa_encrypt(RSA.importKey(self.PU_AS), bytes(key, encoding="utf-8"))
                    # encrypt message
                    msg_enc = symmetric_encrypt(key, json.dumps(msg))
                    data = json.dumps({"message": msg_enc.decode("utf-8"), "key": key_enc.hex()})
                    # send message
                    s.sendall(bytes(data, encoding="utf-8"))
                    # next state
                    self.state = 3
                if (self.state == 3 and name == "AS"):
                    data = s.recv(1024)
                    data = data.decode(encoding="utf-8")
                    #TODO check TS and LT
                    #TODO   save PU_VS vote_cert SK_voter
                    #TODO   check hash
                    self.state = 4
                if (self.state == 4 and name == 'VS'):
                    data = {"message": "PU_VS[vote, E_SK[hash[vote], vote_cert, PR_C[hash[M]]]"}
                    data = json.dumps(data)
                    s.sendall(bytes(data, encoding="utf-8"))
                    self.state = 5
                if (self.state == 5 and name == 'VS'):
                    data = s.recv(1024)
                    data = data.decode(encoding="utf-8")
                    #TODO check TS and LT
                    #TODO   check hash and status
                    self.state = 6
                if (self.state == 6):
                    s.close()


    def verify_sign(self, PU, signature, data):
        signer = PKCS1_v1_5.new(PU)
        digest = SHA256.new()
        digest.update(data)
        if signer.verify(digest, b64decode(signature)):
            return True
        else:
            return False


    def sign_data(self, PR, data):
        signer = PKCS1_v1_5.new(PR)
        digest = SHA256.new()
        digest.update(data)
        sign = signer.sign(digest)
        return b64encode(sign)


    def initiate(self):
        t1 = threading.Thread(target=self.connect, args=(8087, "CA"))
        t2 = threading.Thread(target=self.connect, args=(8088, "AS"))
        t3 = threading.Thread(target=self.connect, args=(8089, "VS"))
        t1.start()
        t2.start()
        t3.start()
        t1.join()
        t2.join()
        t3.join()

c = Client('0000000001', 'Arman')
c.initiate()
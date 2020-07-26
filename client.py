import socket, json, threading, binascii, random, string, codecs
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from encrypt_decrypt import rsa_encrypt
from sha_hash import sha_hash
from symmetric_enc_dec import symmetric_encrypt, symmetric_decrypt

class Client:
    HOST = "127.0.0.1"
    CA_FLAG = False
    AS_FLAG = False
    VS_FLAG = False
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
                    M = str(self.ID) + self.NAME
                    signature = symmetric_encrypt(str(self.ID), sha_hash(bytes(M, encoding="utf-8")))
                    msg = {"ID": self.ID, "NAME": self.NAME, "TS1": 1, "LT1": 10, "signature": signature.decode("utf-8")}
                    key = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k = 5))
                    key_enc = rsa_encrypt("PU_CA.key", bytes(key, encoding="utf-8"))
                    print(len(key_enc))
                    msg_enc = symmetric_encrypt(key, json.dumps(msg))
                    data = json.dumps({"message": msg_enc.decode("utf-8"), "key": key_enc.hex()})
                    s.sendall(bytes(data, encoding="utf-8"))
                    self.state = 1
                if (self.state == 1 and name == "CA"):
                    data = s.recv(1024)
                    data = data.decode(encoding="utf-8")
                    #TODO check TS and LT
                    #TODO   save PU_AS PR_C cert
                    #TODO   check hash
                    self.state = 2
                if (self.state == 2 and name == "AS"):
                    data = {"message": "PU_AS[ID, Cert, TS3, LT3, E_PR_C[hash[M]]]"}
                    data = json.dumps(data)
                    s.sendall(bytes(data, encoding="utf-8"))
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

c = Client(2731237, "Arman")
c.initiate()
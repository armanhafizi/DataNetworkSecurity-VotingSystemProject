import socket, json
from Crypto.PublicKey import RSA
from encrypt_decrypt import rsa_decrypt, rsa_encrypt
from symmetric_enc_dec import symmetric_decrypt
from sha_hash import sha_hash


class CA:
    HOST = "127.0.0.1"

    def __init__(self, port):
        self.PORT = port
        key = RSA.generate(1024)
        pub_key = key.publickey()
        private_key = key.exportKey()
        f = open("PR_CA.key", "wb").write(private_key)
        public_key = pub_key.exportKey()
        f = open("PU_CA.key", "wb").write(private_key)
        

    def initiate(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST, self.PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print('Connected: ', addr)
                data = conn.recv(1024)
                data = json.loads(data)
                msg_enc = data["message"]
                key_enc = bytes.fromhex(data["key"])
                key = rsa_decrypt("PR_CA.key", key_enc)
                message = symmetric_decrypt(key.decode("utf-8"), msg_enc)
                data = json.loads(message)
                enc_signature = data["signature"]
                id = data["ID"]
                name = data["NAME"]
                ts = data["TS1"]
                lt = data["LT1"]
                signature = symmetric_decrypt(str(id), enc_signature)
                if sha_hash(bytes(str(id) + name, encoding="utf-8")) == signature:
                    print("Correct Signature")
                else:
                    print("incorrect signature")
                #TODO check ID and corresponding name
                #TODO check hash
                data = {"message": "K_C[PU_AS, PR_C, cert, TS2, LT2, hash[M]"}
                data = json.dumps(data)
                conn.sendall(bytes(data, encoding="utf-8"))
ca = CA(8087)
ca.initiate()

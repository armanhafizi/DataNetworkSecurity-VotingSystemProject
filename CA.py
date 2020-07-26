import socket, json, random, string
from Crypto.PublicKey import RSA
from encrypt_decrypt import rsa_decrypt, rsa_encrypt
from symmetric_enc_dec import symmetric_decrypt, symmetric_encrypt
from sha_hash import sha_hash


class CA:
    HOST = "127.0.0.1"

    def __init__(self, port):
        self.PORT = port
        

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

                # Create PR PU and send it to client with certificate and signature
                data = {"message": "K_C[PU_AS, PR_C, PR_CA[cert], TS2, LT2, hash[M]"}
                key = RSA.generate(1024)
                pub_key = key.publickey()
                private_key_c = key.exportKey()
                public_key_c = pub_key.exportKey()
                
                public_key_as = open("PU_AS.key", "r", encoding="utf-8").read()
                certification = {"ID": id, "PU_C": public_key_c.decode("utf-8")}
                M = public_key_as + private_key_c.decode("utf-8") + json.dumps(certification)
                
                rand_key_1 = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k = 5))
                key_1_enc = rsa_encrypt("PU_CA.key", bytes(rand_key_1, encoding="utf-8"))
                message_enc_1 = symmetric_encrypt(rand_key_1, json.dumps(certification))
                cert_encrypted = json.dumps({"message": message_enc_1.decode("utf-8"), "key": key_1_enc.hex()})
                
                signature = sha_hash(bytes(M, encoding="utf-8"))

                message = {"PU_AS": public_key_as, "PR_C": private_key_c.decode("utf-8"), "cert_encrypted": cert_encrypted, "TS2": 2, "LT2": 18, "signature": signature}
                data = symmetric_encrypt(str(id) + 'S3', json.dumps(message))
                conn.sendall(data)
ca = CA(8087)
ca.initiate()

import socket, json, random, string
from Crypto.PublicKey import RSA
from encrypt_decrypt import rsa_decrypt, rsa_encrypt
from symmetric_enc_dec import symmetric_decrypt, symmetric_encrypt
from sha_hash import sha_hash
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode

class AS:
    HOST = "127.0.0.1"

    def __init__(self, port):
        self.PORT = port
        f = open('CA_DB/info.txt', 'wt')
        f.write('0000000001,Arman,False\n')
        f.write('0000000002,Amir Hossein,False\n')
        f.write('0000000003,Sepideh,False\n')
        f.write('0000000004,Kiana,False\n')
        f.write('0000000005,Taha,False\n')
        f.close()
        #log = open('CA_log.txt', 'wt')

    def initiate(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST, self.PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print('Connected: ', addr)
                data = conn.recv(4096)
                data = json.loads(data)
                msg_enc = data["message"]
                key_enc = bytes.fromhex(data["key"])
                # decrypt key
                PR_AS = RSA.importKey(open('PR_AS.key', "rb").read())
                key = rsa_decrypt(PR_AS, key_enc)
                # decrypt message
                message = symmetric_decrypt(key.decode("utf-8"), msg_enc)
                data = json.loads(message)
                # extract data
                signature = data["signature"]
                ID_C = data["ID"]
                PU_C = data['PU_C']
                cert_encrypted = data['cert_encrypted']
                ts = data["TS3"]
                lt = data["LT3"]
                # check certification
                certification = {"ID": ID_C, "PU_C": PU_C}
                certification = bytes(json.dumps(certification), encoding = 'utf-8')
                PU_CA = RSA.importKey(open('PU_CA.key', "rb").read())
                status_cert = self.verify_sign(PU_CA, cert_encrypted, certification)
                print('certification:'+str(status_cert))
                # TODO check timestamp
                # check hash
                M = ID_C + cert_encrypted
                if self.verify_sign(RSA.importKey(PU_C), signature, bytes(sha_hash(bytes(M, encoding="utf-8")), encoding='utf-8')):
                    print("Correct Signature")
                    # read database
                    f = open('CA_DB/info.txt', 'r')
                    line = f.readlines()
                    f.close()
                    for i in range(len(line)):
                        # find client
                        if line[i].split(',')[0] == str(id) and line[i].split(',')[1] == name:
                            if line[i].split(',')[2] == 'False\n':
                                # write in database
                                f = open('CA_DB/info.txt', 'w')
                                line[i] = id + ',' + name + ',True\n'
                                line_new = ''.join(line)
                                f.write(line_new)
                                f.close()
                                # generate PU PR for that person
                                PR_NAME = 'CA_DB/PR_' + str(id) + '.key'
                                PU_NAME = 'CA_DB/PU_' + str(id) + '.key'
                                generate_keys(PR_NAME, PU_NAME)
                            # read keys
                            PR_C = open('CA_DB/PR_'+id+'.key', "r", encoding="utf-8").read()
                            PU_C = open('CA_DB/PU_'+id+'.key', "r", encoding="utf-8").read()
                            PU_AS = open("PU_AS.key", "r", encoding="utf-8").read()
                            # certification
                            certification = {"ID": id, "PU_C": PU_C}
                            certification = bytes(json.dumps(certification), encoding = 'utf-8')
                            # sign certification
                            PR_CA = RSA.importKey(open('PR_CA.key', "rb").read())
                            cert_encrypted = self.sign_data(PR_CA, certification)
                            cert_encrypted = cert_encrypted.decode('utf-8')
                            # hash message with signature
                            M = PU_AS + PR_C + cert_encrypted # raw message
                            signature = sha_hash(bytes(M, encoding="utf-8"))
                            # final message
                            message = {"PU_AS": PU_AS, "PR_C": PR_C, 'PU_C': PU_C, "cert_encrypted": cert_encrypted, "TS2": 2, "LT2": 18, "signature": signature}
                            # encrypt message by K_C
                            data = symmetric_encrypt(K_C, json.dumps(message))
                            # send message
                            conn.sendall(data)
                            break
                else:
                    print("Incorrect signature")

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
        
as_ = AS(8088)
as_.initiate()

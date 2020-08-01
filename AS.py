import socket, json, random, string
from Crypto.PublicKey import RSA
from encrypt_decrypt import rsa_decrypt, rsa_encrypt
from symmetric_enc_dec import symmetric_decrypt, symmetric_encrypt
from sha_hash import sha_hash
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode
from datetime import datetime, timedelta

class AS:
    HOST = "127.0.0.1"

    def __init__(self, port):
        self.PORT = port
        f = open('AS_DB/policy.txt', 'wt')
        # ID forbidden age
        f.write('0000000001,False,21\n')
        f.write('0000000002,False,39\n')
        f.write('0000000003,True,23\n')
        f.write('0000000004,False,14\n')
        f.write('0000000005,False,40\n')
        f.close()
        #log = open('AS_DB/log.txt', 'wt')

    def initiate(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.HOST, self.PORT))
            s.listen()
            while True:
                conn, addr = s.accept()
                with conn:
                    print('Connected: ', addr)
                    data = conn.recv(4096)
                    data = json.loads(data)
                    msg_enc = data["message"]
                    key_enc = bytes.fromhex(data["key"])
                    # decrypt key
                    PR_AS = open('PR_AS.key', "rb").read()
                    key = rsa_decrypt(RSA.importKey(PR_AS), key_enc)
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
                    # check timestamp
                    t1 = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')
                    t2 = datetime.now()
                    l = datetime.strptime(lt, '%H:%M:%S')
                    delta = timedelta(hours=l.hour, minutes=l.minute, seconds=l.second)
                    status_time = False
                    if t2-t1 <= delta:
                        status_time = True
                    print('Timestamp Status:'+str(status_time))
                    # check hash
                    M = ID_C + PU_C + cert_encrypted
                    status_hash = False
                    if self.verify_sign(RSA.importKey(PU_C), signature, bytes(sha_hash(bytes(M, encoding="utf-8")), encoding='utf-8')):
                        status_hash = True
                    print('Hash Status:' + str(status_hash))
                    # check certification
                    certification = {"ID": ID_C, "PU_C": PU_C}
                    certification = bytes(json.dumps(certification), encoding = 'utf-8')
                    PU_CA = open('PU_CA.key', "rb").read()
                    status_cert = self.verify_sign(RSA.importKey(PU_CA), cert_encrypted, certification)
                    print('Certification Status:' + str(status_cert))
                    if status_hash == False:
                        # final message
                        msg = {'validity':'NO', 'error': 'server: Wrong Hash'}
                    elif status_time == False:
                        # final message
                        msg = {'validity':'NO', 'error': 'server: Timstamp Expired'}
                    elif status_cert == False:
                        # final message
                        msg = {'validity':'NO', 'error': 'server: Wrong Certification'}
                    else: # every thing is fine
                        # read database
                        f = open('AS_DB/policy.txt', 'r')
                        line = f.readlines()
                        f.close()
                        for i in range(len(line)):
                            # find client
                            l = line[i].split(',')
                            if l[0] == ID_C:
                                if l[1] == 'False' and int(l[2][0:-1]) >= 16: # check policy
                                    # read keys
                                    PR_AS = open('PR_AS.key', 'r', encoding="utf-8").read()
                                    PU_AS = open('PU_AS.key', 'r', encoding="utf-8").read()
                                    PU_VS = open('PU_VS.key', 'r', encoding="utf-8").read()
                                    # sign hash of ticket
                                    SK_voter = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 5))
                                    ticket = SK_voter + PU_C
                                    ticket_signature = self.sign_data(RSA.importKey(PR_AS), bytes(sha_hash(bytes(ticket, encoding="utf-8")),encoding="utf-8"))
                                    ticket_signature = ticket_signature.decode('utf-8')
                                    # encrypt ticket
                                    msg = {'SK_voter': SK_voter, 'PU_C': PU_C, 'signature': ticket_signature}
                                    # encrypt key - ticket
                                    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 5))
                                    key_enc = rsa_encrypt(RSA.importKey(PU_VS), bytes(key, encoding="utf-8"))
                                    # encrypt message - ticket
                                    msg_enc = symmetric_encrypt(key, json.dumps(msg))
                                    ticket_encrypted = json.dumps({"message": msg_enc.decode("utf-8"), "key": key_enc.hex()})
                                    # sign hash of message
                                    M = ticket_encrypted + SK_voter + PU_VS
                                    signature = self.sign_data(RSA.importKey(PR_AS) , bytes(sha_hash(bytes(M, encoding="utf-8")),encoding="utf-8"))
                                    signature = signature.decode('utf-8')
                                    # timestamp
                                    TS4 = datetime.now()
                                    LT4 = timedelta(seconds=5)
                                    # final message
                                    msg = {'validity': 'YES', 'ticket_encrypted': ticket_encrypted,'SK_voter': SK_voter, 'PU_VS': PU_VS, 'TS4': str(TS4), 'LT4': str(LT4), 'signature': signature}
                                else: # not allowed to vote
                                    msg = {'validity':'NO', 'error': 'server: NOT Allowed to Vote'}
                                break
                    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 5))
                    # encrypt key
                    key_enc = rsa_encrypt(RSA.importKey(PU_C), bytes(key, encoding="utf-8"))
                    # encrypt message
                    msg_enc = symmetric_encrypt(key, json.dumps(msg))
                    data = json.dumps({"message": msg_enc.decode("utf-8"), "key": key_enc.hex()})
                    # send message
                    conn.sendall(bytes(data, encoding="utf-8"))

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
        
as_ = AS(1981)
as_.initiate()

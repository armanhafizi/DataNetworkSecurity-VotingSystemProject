import socket, json, random, string
from Crypto.PublicKey import RSA
from encrypt_decrypt import rsa_decrypt, rsa_encrypt
from symmetric_enc_dec import symmetric_decrypt, symmetric_encrypt
from sha_hash import sha_hash
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode
from datetime import datetime, timedelta

class VS:
    HOST = "127.0.0.1"

    def __init__(self, port):
        self.PORT = port
        f = open('VS_DB/results.txt', 'wt')
        # option1 option2 option3
        f.write('0,0,0')
        f.close()
        f = open('VS_DB/voters.txt', 'wt')
        # list of public keys
        f.close()
        log = open('AS_DB/log.txt', 'wt')
        log.close()

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
                    PR_VS = open('PR_VS.key', "rb").read()
                    key = rsa_decrypt(RSA.importKey(PR_VS), key_enc)
                    # decrypt message
                    message = symmetric_decrypt(key.decode("utf-8"), msg_enc)
                    # logging received data
                    log = open('VS_DB/log.txt', 'a')
                    log.write('received from {}: '.format(addr))
                    log.write(message)
                    log.write('\n')
                    log.close()
                    data = json.loads(message)
                    # extract data
                    signature = data['signature']
                    vote = data['vote']
                    vote_encrypted = data['vote_encrypted']
                    ticket_encrypted = data['ticket_encrypted']
                    # check hash
                    M = vote + vote_encrypted.encode('utf-8').hex() + ticket_encrypted
                    status_hash = False
                    if sha_hash(bytes(M, encoding='utf-8')) == signature:
                        status_hash = True
                    print('Hash Status:' + str(status_hash))
                    # check ticket validity
                    msg_enc = json.loads(ticket_encrypted)['message']
                    key_enc = bytes.fromhex(json.loads(ticket_encrypted)['key'])
                    # decrypt key
                    key = rsa_decrypt(RSA.importKey(PR_VS), key_enc)
                    # decrypt message
                    message = symmetric_decrypt(key.decode('utf-8'), msg_enc)
                    data = json.loads(message)
                    # extract data
                    SK_voter = data['SK_voter']
                    PU_C = data['PU_C']
                    signature = data['signature']
                    ticket = SK_voter + PU_C
                    PU_AS = open('PU_AS.key', 'r').read()
                    # Handle bad vote option(send error if vote is not 1, 2 or 3)
                    if (not(vote == "1" or vote == "2" or vote == "3")):
                        msg = {'validity':'NO', 'error': 'server: Incorrect vote number'}
                        # logging sent data
                        log = open('VS_DB/log.txt', 'a')
                        log.write('sent to {}: '.format(addr))
                        log.write(json.dumps(msg))
                        log.write('\n')
                        log.close()
                        key = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 5))
                        key_enc = rsa_encrypt(RSA.importKey(PU_C), bytes(key, encoding="utf-8"))
                        msg_enc = symmetric_encrypt(key, json.dumps(msg))
                        data = json.dumps({'message': msg_enc.decode("utf-8"), 'key': key_enc.hex()})
                        conn.sendall(bytes(data, encoding="utf-8"))
                        continue
                    status_ticket = self.verify_sign(RSA.importKey(PU_AS), signature, bytes(sha_hash(bytes(ticket, encoding="utf-8")),encoding="utf-8"))
                    print('Ticket Status:'+str(status_ticket))
                    # check vote hash
                    vote_decrypted = symmetric_decrypt(SK_voter, vote_encrypted)
                    status_vote = False
                    if sha_hash(bytes(vote, encoding='utf-8')) == vote_decrypted:
                        status_vote = True
                    print('Vote Status:' + str(status_vote))
                    if status_hash == False:
                        # final message
                        msg = {'validity':'NO', 'error': 'server: Wrong Hash'}
                    elif status_ticket == False:
                        # final message
                        msg = {'validity':'NO', 'error': 'server: Invalid Vote Ticket'}
                    elif status_vote == False:
                        # final message
                        msg = {'validity':'NO', 'error': 'server: Vote Encrypted Wrongly'}
                    else: # every thing is fine
                        # read database
                        f = open('VS_DB/voters.txt', 'r')
                        line = f.read()
                        f.close()
                        voters = line.split(',')
                        status = '' # save voting process status
                        if PU_C in voters: # had voted before
                            status = 'Error: UNSUCCESSFUL'
                        else:
                            status = 'SUCCESSFUL'
                            # write to database
                            # add voter to the voters
                            f = open('VS_DB/voters.txt', 'wt')
                            line_new = line + ',' + PU_C
                            f.write(line_new)
                            f.close()
                            # add vote to the votes
                            f = open('VS_DB/results.txt', 'r')
                            line = f.read()
                            f.close()
                            line = line.split(',')
                            line_new
                            if vote == '1':
                                line_new = str(int(line[0])+1) + ',' + line[1] + ',' + line[2]
                            elif vote == '2':
                                line_new = line[0] + ',' + str(int(line[1])+1) + ',' + line[2]
                            elif vote == '3':
                                line_new = line[0] + ',' + line[2] + ',' + str(int(line[1])+1)
                            f = open('VS_DB/results.txt', 'w')
                            f.write(line_new)
                            f.close()
                        # sign hash of message
                        signature = self.sign_data(RSA.importKey(PR_VS) , bytes(sha_hash(bytes(status, encoding="utf-8")),encoding="utf-8"))
                        signature = signature.decode('utf-8')
                        # final message
                        msg = {'validity': 'YES', 'status': status, 'signature': signature}
                    # logging sent data
                    log = open('VS_DB/log.txt', 'a')
                    log.write('sent to {}: '.format(addr))
                    log.write(json.dumps(msg))
                    log.write('\n')
                    log.close()
                    # encrypt key
                    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 5))
                    key_enc = rsa_encrypt(RSA.importKey(PU_C), bytes(key, encoding="utf-8"))
                    # encrypt message
                    msg_enc = symmetric_encrypt(key, json.dumps(msg))
                    data = json.dumps({'message': msg_enc.decode("utf-8"), 'key': key_enc.hex()})
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
        
vs_ = VS(1982)
vs_.initiate()

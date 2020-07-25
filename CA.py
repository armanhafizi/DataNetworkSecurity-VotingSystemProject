import socket, json
from OpenSSL import crypto, SSL

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
                print("Received: ", data.decode(encoding="utf-8"))
                #TODO check ID and corresponding name
                #TODO check hash
                data = {"message": "K_C[PU_AS, PR_C, cert, TS2, LT2, hash[M]"}
                data = json.dumps(data)
                conn.sendall(bytes(data, encoding="utf-8"))
ca = CA(8087)
ca.initiate()

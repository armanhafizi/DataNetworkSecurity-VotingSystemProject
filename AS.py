import socket, json

HOST = "127.0.0.1"
PORT = 8088

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected: ', addr)
        data = conn.recv(1024)
        print("Received: ", data.decode(encoding="utf-8"))
        #TODO save ID cert
        #TODO check hash
        data = {"message": "PU_C[vote_cert, SK_Voter, PU_VS, TS4, LT4, E_PR_AS[hash[M]]]"}
        data = json.dumps(data)
        conn.sendall(bytes(data, encoding="utf-8"))        

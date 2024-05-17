import socket
from utils import *
from ntru import NTRUKey, generate_key
from poly import Polynomial as poly
import pickle
import sys
import time


class client:

    def __init__(self, K1_, id_, f_, A_, B_, n_):
        self.K1 = K1_
        self.id = id_
        self.f = f_
        self.A = A_
        self.B = B_
        self.n = n_

    # def sync_message(self, str):
    #     # print([0, self.an, self.bn, hash_function([self.K, self.id, self.c, self.an, self.bn, self.n])],"\n\n\n\n")
    #     return [
    #         0,
    #         self.an,
    #         self.bn,
    #         hash_function([self.K, self.id, self.c, self.an, self.bn, self.n]),
    #     ]

    # def desync_message(self, str):
    #     rn = get_random()
    #     yn = self.an ^ self.id ^ rn
    #     zn = hash_function([self.K, rn, yn])
    #     return [
    #         1,
    #         self.an,
    #         self.bn,
    #         yn,
    #         zn,
    #         hash_function([self.K, self.id, self.c, self.an, self.bn, self.n, zn]),
    #     ]


def main():

    # mobile = client(3452345, 234562345, 1010, 23456, 567890)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((host, port))
    print("Connected to server on {}:{}".format(host, port))

    # ****************** Registration Phase ******************

    init_message = pickle.loads(client_socket.recv(8192))
    mobile = client(
        init_message[2],  # K1
        init_message[5],  # id
        init_message[3],  # f
        init_message[0],  # A
        init_message[1],  # B
        init_message[4],  # n
    )
    
    # ****************** Generating NTRU and sharing public key(Client Side) ******************

    server_pk = pickle.loads(client_socket.recv(8192))


    keys = generate_key()
    client_h = keys._h
    client_socket.sendall(pickle.dumps(client_h))
    # # print(keys.get_h)
    # send(client_socket, client_h.coefficients())

    # ****************** Phase 1  (UE --(A, B, F1, f, I, J)--> HN) ******************

    r2 = get_random()
    I = hash_function([mobile.K1]) ^ r2
    J = mobile.n ^ hash_function([mobile.K1, r2])
    # F1 = H(Uid || H(K1) || f || r2 || n)
    F1 = hash_function([mobile.id, hash_function([mobile.K1]), mobile.f, r2, mobile.n])
    mobile.n += 1

    reply = [mobile.A, mobile.B, F1, mobile.f, I, J]
    # print(reply)

    # Encrypting and sending (A, B, F1, f, I, J)
    reply = serialize(
        reply
    )  # encodes reply into a polynomial of form {-1, 0, 1}^(20*len(reply))
    reply = keys.encrypt(reply, server_pk)  # encrypts reply using server's public key
    # print(reply)
    
    
    client_socket.sendall(
        pickle.dumps(reply)
    )  # sends the encrypted polynomial through socket
    

    # ****************** Phase 3 ******************
    # Recieves (D1, D2, D3, F2) from HN as msg
    # msg[0] -> D1
    # msg[1] -> D2
    # msg[2] -> D3
    # msg[3] -> F2

    msg = pickle.loads(
        client_socket.recv(BUFF_SIZE)
    )  # recieves the encrypted polynomial sent through socket
    msg = keys.decrypt(msg)  # decrypts the polynomial
    
    msg = deserialize(
        msg
    )  # deserializes msg to plain text from {-1, 0, 1}^(20*len(reply))

    k1_new = msg[0] ^ mobile.K1 ^ r2
    K_SEAF = hash_function([r2, mobile.K1, mobile.n + 1])
    A_new = msg[1] ^ hash_function([k1_new, r2])
    B_new = msg[2] ^ hash_function([r2, k1_new])
    F2_ = hash_function([K_SEAF, A_new, B_new])
    if msg[3] != F2_:
        abort()

    mobile.K1 = k1_new
    mobile.A = A_new
    mobile.B = B_new
    mobile.f = (mobile.f + 1) % 2
    

    print("Authentication Successful")


    while True:

        message = input("Enter message to send to server (type 'exit' to quit): ")
        client_socket.send(message.encode("utf-8"))

        if message.lower() == "exit":
            break

        response = client_socket.recv(1024).decode("utf-8")
        print("Received from server:", response)

    client_socket.close()


if __name__ == "__main__":
    main()

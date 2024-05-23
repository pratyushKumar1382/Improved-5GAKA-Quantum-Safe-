import socket
from utils import *
from ntru import NTRUKey, generate_key
import pickle
import time
import sys 
N = 5
p = 3
q = 2051


class server:

    def __init__(self, km):
        self.registered_clients = {}
        self.km = km
        self.deln = 100

    def add_client(self, id, K1, K, n):
        self.registered_clients[id] = [[K1, K], n]


def main():

    HN = server(567890)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((host, port))

    server_socket.listen(5)
    print("Server listening on {}:{}".format(host, port))

    client_socket, addr = server_socket.accept()
    print("Connection from {}".format(addr))

    # client_socket.sendall(pickle.dumps([1,2,3,4]))


    # ****************** Generating NTRU keys and sharing public key(Server Side) ******************

    # keys = generate_key()
    # server_h = keys._h
    # print(server_h)
    # print(type(server_h))
    # print(sys.getsizeof(pickle.dumps(server_h)))
    # print()
    # client_socket.sendall(pickle.dumps(server_h))
    # print("1")
    # client_pk = pickle.loads(client_socket.recv(BUFF_SIZE))


    # ****************** Registration Phase ******************

    r1 = get_random()
    print("r1", r1)
    K = get_random()
    print("hello")
    A = 234562345 ^ hash_function([HN.km, r1])
    B = A ^ r1 ^ HN.km
    K1 = hash_function([K, r1])
    print("K1 ",K1)
    # send (A, B, K1, f, n, Uid)
    # print(sys.getsizeof(pickle.dumps([A, B, K1, 0, 0, 234562345])))
    client_socket.sendall(pickle.dumps([A, B, K1, 0, 0, 234562345]))
    print([A, B, K1, 0, 0, 234562345])
    HN.add_client(234562345, K1, K, 0)


    # ****************** Phase 2 ******************
    # Recieves (A, B, F1, f, I, J) from client as msg
    # start_time = time.perf_counter()

    msg = pickle.loads(
        client_socket.recv(BUFF_SIZE)
    )  # recieves the encrypted polynomial sent through socket
    print(msg)
    # msg = keys.decrypt(msg)  # decrypts the polynomial
    # msg = deserialize(
    #     msg
    # )  # deserializes msg to plain text from {-1, 0, 1}^(20*len(reply))
    print(msg)

    # msg[0] -> A
    # msg[1] -> B
    # msg[2] -> F1
    # msg[3] -> f
    # msg[4] -> I
    # msg[5] -> J
    # HN.registered_clients[id][0] -> K[], msg[3] -> f
    # ==> HN.registered_clients[id][0][msg[3]] = K[f]
    print("I: ",msg[4])
    print("r1", msg[0] ^ msg[1] ^ HN.km )
    id = msg[0] ^ hash_function([HN.km, msg[0] ^ msg[1] ^ HN.km])
    print("K1 ", HN.registered_clients[id][0][msg[3]])
    print("ytf",hash_function([HN.registered_clients[id][0][msg[3]], msg[0] ^ msg[1] ^ HN.km]))
    # r2 = msg[4] ^ hash_function(
    #     [hash_function([HN.registered_clients[id][0][msg[3]], msg[0] ^ msg[1] ^ HN.km])]
    # )
    r2 = msg[4] ^ hash_function([K1])
    print("erg", hash_function(
        [hash_function([HN.registered_clients[id][0][msg[3]], msg[0] ^ msg[1] ^ HN.km])]
    ))
    print("r2", r2)
    # n_ = msg[5] ^ hash_function(
    #     [
    #         hash_function(
    #             [HN.registered_clients[id][0][msg[3]], msg[0] ^ msg[1] ^ HN.km]
    #         ),
    #         r2,
    #     ]  # mistake
    # )
    n_ = msg[5] ^ hash_function([K1, r2])
    print("id", id, r2, HN.registered_clients[id][1], n_)
    if HN.registered_clients[id][1] < n_:
        abort("1")
    flag = 1
    for delta in range(HN.deln):
        F1_ = hash_function(
            [
                id,
                hash_function(
                    [
                        K1
                    ]
                ),
                msg[3],
                r2,
                HN.registered_clients[id][1] - delta,
            ]
        )
        if msg[2] == F1_:
            flag = 0
            HN.registered_clients[id][1] -= delta
            break
    if flag:
        abort("2")

    HN.registered_clients[id][1] += 1  # HN.registered_clients[id][1] -> n
    r3 = get_random()
    K_new = get_random()
    A_new = id ^ hash_function([HN.km, r3])
    B_new = A_new ^ r3 ^ HN.km
    print("Anew", A_new, B_new)
    k1_new = hash_function([K_new, r3])
    K_SEAF = hash_function(
        [
            r2,
            K1,
            HN.registered_clients[id][1] + 1,
        ]
    )
    print("KSEAF ", K_SEAF)
    print([
            r2,
            K1,
            HN.registered_clients[id][1] + 1,
        ])

    D1 = (
        k1_new
        ^ K1
        ^ r2
    )
    D2 = A_new ^ hash_function([k1_new, r2])
    D3 = B_new ^ hash_function([r2, k1_new])
    F2 = hash_function([K_SEAF, A_new, B_new])
    HN.registered_clients[id][0][(msg[3] + 1) % 2] = K_new

    # Encrypting and sending (D1, D2, D3, D4) to UE
    reply = [D1, D2, D3, F2]

    # reply = serialize(
    #     reply
    # )  # encodes reply into a polynomial of form {-1, 0, 1}^(20*len(reply))
    # reply = keys.encrypt(reply, client_pk)  # encrypts reply using client's public key
    
    client_socket.sendall(
        pickle.dumps(reply)
    )  
    print(reply)
    # end_time = time.perf_counter()
    # print("Time Taken in decryption: ", end_time - start_time, " s\n")
    print("Authentication Succesful")

    while True:

        data = client_socket.recv(1024).decode("utf-8")
        print("Received from client:", data)

        if data.lower() == "exit":
            break

        response = input("Enter message to send to client: ")
        client_socket.send(response.encode("utf-8"))

    client_socket.close()


if __name__ == "__main__":
    main()

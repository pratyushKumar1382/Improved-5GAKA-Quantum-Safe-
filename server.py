import socket
from utils_server import *
import pickle
import time
import sys 



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
    print("\nRegistration phase\n")
    r1 = get_random()
    K = get_random()
    A = 234562345 ^ hash_function([HN.km, r1])
    B = A ^ r1 ^ HN.km
    K1 = hash_function([K, r1])
    # print(sys.getsizeof(pickle.dumps([A, B, K1, 0, 0, 234562345])))
    client_socket.sendall(pickle.dumps([A, B, K1, 0, 0, 234562345]))
    print("Msg sent by HN to UE [A, B, K1, f, n, UEid]")
    print([A, B, K1, 0, 0, 234562345])
    HN.add_client(234562345, K, K1, 0)


    # ****************** Phase 2 ******************
    # Recieves (A, B, F1, f, I, J) from client as msg
    # start_time = time.perf_counter()
    print("\n Authentication Phase\n")

    msg = pickle.loads(
        client_socket.recv(BUFF_SIZE)
    )  # recieves the encrypted polynomial sent through socket

    # msg = keys.decrypt(msg)  # decrypts the polynomial
    # msg = deserialize(
    #     msg
    # )  # deserializes msg to plain text from {-1, 0, 1}^(20*len(reply))
    print("Message recieved from UE [A, B, F1, f, I, J]\n")
    print(msg,"\n")


    # msg[0] -> A
    # msg[1] -> B
    # msg[2] -> F1
    # msg[3] -> f
    # msg[4] -> I
    # msg[5] -> J
    # HN.registered_clients[id][0] -> K[], msg[3] -> f
    # ==> HN.registered_clients[id][0][msg[3]] = K[f]

    id = msg[0] ^ hash_function([HN.km, msg[0] ^ msg[1] ^ HN.km])
    hashed_value = hash_function([HN.registered_clients[id][0][msg[3]], msg[0] ^ msg[1] ^ HN.km])
    # hashed_value -> H(K[f], A^B^km)

    # r2 = msg[4] ^ hash_function(
    #     [hash_function([HN.registered_clients[id][0][msg[3]], msg[0] ^ msg[1] ^ HN.km])]
    # )
    r2 = msg[4] ^ hash_function([hashed_value])

    # n_ = msg[5] ^ hash_function(
    #     [
    #         hash_function(
    #             [HN.registered_clients[id][0][msg[3]], msg[0] ^ msg[1] ^ HN.km]
    #         ),
    #         r2,
    #     ]  # mistake
    # )
    # print(hash_function([HN.registered_clients[id][0][msg[3]], msg[0] ^ msg[1] ^ HN.km]))
    n_ = msg[5] ^ hash_function([hashed_value, r2])
    # print("id", id, r2, HN.registered_clients[id][1], n_)
    if HN.registered_clients[id][1] < n_:
        abort()
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
    k1_new = hash_function([K_new, r3])
    K_SEAF = hash_function(
        [
            r2,
            hashed_value,
            HN.registered_clients[id][1] + 1,
        ]
    )
    print("Session Key: ", K_SEAF, "\n")
    D1 = (
        k1_new
        ^ hashed_value
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
    print("Msg sent by HN to UE [D1, D2, D3, F2]\n")
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

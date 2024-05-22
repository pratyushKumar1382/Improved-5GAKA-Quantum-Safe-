import json
import hashlib
from poly import Polynomial as poly
from ntru import NTRUKey, generate_key
import hashlib
import random

host = "0.0.0.0"
port = 9123
BUFF_SIZE = 5120000


def receive_list(client_socket):
    data = client_socket.recv(1024).decode("utf-8")
    received_list = json.loads(data)
    return received_list


def send_list(client_socket, data_list):
    message = json.dumps(data_list)
    client_socket.send(message.encode("utf-8"))


def hash_function(lst):
    # ans = len(lst)
    # itr = 0
    # while itr < len(lst):
    #     ans = ans ^ lst[itr] | itr
    #     itr += 1
    # return ans
    # Convert the list to a string representation
    list_str = ''.join(str(elem) for elem in lst)

    # Hash the string using SHA-512
    hash_object = hashlib.sha256(list_str.encode())

    # Get the hexadecimal representation of the hash
    hex_dig = hash_object.hexdigest()

    # Convert the hexadecimal hash to an integer
    hash_int = int(hex_dig, 16)

    return hash_int


def abort():
    print("aborted")
    return 0


def get_random():
    return random.randrange(1000000, 99999999, 1)
    return 3


# def deserialize(msg, ele=0):
#     lst = []
#     for ms in msg:
#         lst.append(ms)
#     itr = 0
#     if ele:
#         while len(lst) != ele * 20:
#             lst.append(0)

#     response = []
#     while itr < len(lst):
#         itr1 = 0
#         val = 0
#         mul = 1
#         while itr1 < 20 and itr + itr1 < len(lst):
#             addr = lst[itr + itr1]
#             if addr == -1:
#                 addr = 2
#             val += addr * mul
#             mul *= 3
#             itr1 += 1
#         response.append(val)
#         itr += 20
#     return response

def deserialize(msg, ele=0):
    lst = list(msg)
    required_length = ele * 20

    if ele:
        lst.extend([0] * (required_length - len(lst)))

    response = []
    power_of_3 = [3**i for i in range(20)]
    
    for i in range(0, len(lst), 20):
        val = sum((2 if lst[i + j] == -1 else lst[i + j]) * power_of_3[j] for j in range(min(20, len(lst) - i)))
        response.append(val)

    return response



def serialize(msg):
    lst = []
    for ms in msg:
        itr = 0
        while itr < 20:
            val = ms % 3
            if val == 2:
                val = -1
            lst.append(val)
            itr += 1
            ms = int(ms / 3)
            # print(val,ms)
    # print(lst)
    return poly(lst, len(lst))

def serialize_poly(ply):
    lst = []
    for coeff in ply:
        lst.append(coeff)
    return lst

# def send_message(msg, pk, keys):
#     msg = serialize(msg)
#     msg = keys.encrypt(msg,pk)
#     return msg

# def recieve_message(msg, keys):


if __name__ == "__main__":
    print("utils")
    print(serialize([25, 30, 81]))

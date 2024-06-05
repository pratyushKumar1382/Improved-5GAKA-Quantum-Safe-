import hashlib
import random


host = "0.0.0.0"
port = 9132
BUFF_SIZE = 5120000




def hash_function(lst):
    # Convert the list to a string representation
    # start_time = time.perf_counter()
    list_str = ''.join(str(elem) for elem in lst)

    # Hash the string using SHA-512
    hash_object = hashlib.sha256(list_str.encode())

    # Get the hexadecimal representation of the hash
    hex_dig = hash_object.hexdigest()

    # Convert the hexadecimal hash to an integer
    hash_int = int(hex_dig, 16)
    # end_time = time.perf_counter()
    # print("Time taken in computing hash: ", end_time - start_time, " s\n")

    return hash_int


def abort(str = ""):
    print("aborted", str)
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




if __name__ == "__main__":
    print("utils")

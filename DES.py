# Andrew Perez-Napan
# ap16at
# Due Date: 3-31-21
# The program in this file is the individual work of Andrew Perez-Napan
# Used http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm for a better understanding of the workings of DES
# Formatting is sometimes messed up if the encrypted message returns specific characters


import sys
import random
import time


# Initial Permutation
IP = [58, 50, 42, 34, 26, 18, 10,  2, 
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7]


# Expansion Permutation
E = [32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1]


# Making 48-bit key from 56-bit key
PC2 = [14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32]


# Shrink 48 bits to 32 bits
SBOX = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]


# Internediary Permutation
P = [16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25]


# Final Permutation
IPF = [40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25]


# Returns string result of using xor on two binary strings
def xor(one, two):
    out = []
    for i in range(len(one)):
        p = int(one[i])
        q = int(two[i])
        res = int(bool(p) ^ bool(q))
        out.append(res)
    return ''.join(map(str, out))


# Permutation is done on input_ using whatever Array is specified
# in per_type and new size is given specified bu size
def permutate(per_type, input_, size):
    out = [-1] * size
    for i in range(len(per_type)):
        out[i] = input_[per_type[i] - 1]
    return ''.join(map(str, out))


# Circular left shift done on the random key for every new string
def left_shift(key):
    return (key << 1) | (key >> 55)


# Returns a string representing a binary number created from an integer
def int_to_binary(num, bits):
    s = str(bin(num))[2:].rjust(bits, '0')
    return s


# Returns a string of characters formed from corresponding 8-bit blocks
def binary_to_txt(string_):
    s = ""
    for block in split_to_char(string_):
        s += chr(int(block, 2))
    return s


# Splits a binary string into 8-bit blocks
def split_to_char(msg):
    split_txt = []
    for i in range(0, len(msg), 8):
        block = msg[i:i+8]
        split_txt.append(block)
    return split_txt


# Splits the message into 64-bit blocks
def split(msg):
    split_txt = []
    binary_text = ''.join(format(ord(i), '08b') for i in msg)
    while len(binary_text) % 64 != 0:
        binary_text += "0"
    for i in range(0, len(binary_text), 64):
        block = binary_text[i:i+64]
        split_txt.append(block)
    return split_txt


# Encrypts the message by applying DES
def encrypt(msg, key):
    cyphertext = ""
    for block in split(msg):
        num = int(block, 2)
        cyphertext += DES(num, key)
    cyphertext = binary_to_txt(cyphertext)
    return str(cyphertext)


# Decrypts the ciphertext by applying DES
def decrypt(ciphertext, key):
    plaintext = ""
    for block in split(ciphertext):
        num = int(block, 2)
        plaintext += DES(num, key)
    plaintext = binary_to_txt(plaintext)
    return str(plaintext)

# DES
def DES(num, key):
    # Initial Permutation
    ip = permutate(IP, int_to_binary(num, 64), 64)

    # Splits the message into two 32-bit halves
    mid = int(len(ip) / 2)
    left_msg = ip[:mid]
    right_msg = ip[mid:]

    # shifts key and applies PC-2 to shrink to 48 bits
    left_shift(key)
    key_ = permutate(PC2, int_to_binary(key, 56), 48)

    # 16 ROUNDS
    for i in range(0, 16, 1):
        # Expansion permutation on right half of message to 48 bits
        e = permutate(E, right_msg, 48)
        # Applies xor on the new key and expanded right half
        ex_or = xor(key_, e)
        s = []
        # Uses S-Box to shrink right half back down
        for block in range(int(len(ex_or)/6)):
            x = 6 * block
            y = (6 * block) + 6
            blk = ex_or[x:y]
            i = int(blk[0])*2 + int(blk[-1]*1)
            j = (int(blk[1])*8 + int(blk[2])*4 + int(blk[3])*2 + int(blk[4])*1)
            s.append(int_to_binary(SBOX[i][j], 4).rjust(4, '0'))
        s = ''.join(s)
        # Intermediary Permutation
        inter_perm = permutate(P, s, 32)
        # Switching the halves
        temp_msg = xor(left_msg, inter_perm)
        left_msg = right_msg
        right_msg = temp_msg
    # One last switch of the two halves and a Final Permutation
    temp = left_msg
    left_msg = right_msg
    right_msg = temp
    return permutate(IPF, left_msg+right_msg, 64)


if __name__ == "__main__":
    random.seed(time.time())
    key = random.getrandbits(56)

    print("DES Implementation:")
    str_input = input("Enter text to encrypt (\"Exit\" to quit): ")

    if str_input == "Exit":
        exit()
    else:
        print("Encrypted text: '", encrypt(str_input, key), "'")
        print("Decrypted text: '", decrypt(encrypt(str_input, key), key), "'")
        while str_input != "Exit":
            str_input = input("Next text (\"Exit\" to quit): ")
            if str_input == "Exit":
                exit()
            else:
                key = random.getrandbits(56)
                print("Encrypted text: '", encrypt(str_input, key), "'")
                print("Decrypted text: '", decrypt(encrypt(str_input, key), key), "'")

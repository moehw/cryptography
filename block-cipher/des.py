#!/usr/bin/env python3

from binascii import hexlify

from blockcipher import *

# initial permutation for data
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9,  1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# initial permutation-choice on the key
PC_1 = [57, 49, 41, 33, 25, 17, 9,
        1,  58, 50, 42, 34, 26, 18,
        10, 2,  59, 51, 43, 35, 27,
        19, 11, 3,  60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7,  62, 54, 46, 38, 30, 22,
        14, 6,  61, 53, 45, 37, 29,
        21, 13, 5,  28, 20, 12, 4]

# permutation-choice for shifted key to get Ki+1
PC_2 = [14, 17, 11, 24, 1,  5,  3,  28,
        15, 6,  21, 10, 23, 19, 12, 4,
        26, 8,  16, 7,  27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

# expansion data of 32bits to get 48bits to apply the xor with Ki
E = [32, 1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9,  10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S-boxs
S_BOX = [
         
[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
 [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
 [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
 [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
],

[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
 [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
 [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
 [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
],

[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
 [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
 [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
 [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
],

[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
 [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
 [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
 [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
],  

[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
 [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
 [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
 [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
], 

[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
 [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
 [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
 [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
], 

[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
 [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
 [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
 [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
],
   
[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
 [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
 [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
 [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]
]

# permutation after S-box
P = [16, 7,  20, 21, 29, 12, 28, 17,
     1,  15, 23, 26, 5,  18, 31, 10,
     2,  8,  24, 14, 32, 27, 3,  9,
     19, 13, 30, 6,  22, 11, 4,  25]

# final permutation for data after the 16 rounds (inverse IP)
IP_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9,  49, 17, 57, 25]

# shift for each round of keys
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
         3, 2] # for whitening

class DES:
    def __init__(self, key, mode=ECB, iv=None, whitening=False):
        self.iv = iv
        self.key = key
        self.rounds = 16
        self.k1 = None
        self.k2 = None
        if whitening:
            self.subkeys = gen_subkeys(key, self.rounds + 2)
            self.k1 = self.subkeys[-2].ljust(8, '\x00')
            self.k2 = self.subkeys[-1].ljust(8, '\x00')
        else:
            self.subkeys = gen_subkeys(key, self.rounds)

        if VERBOSE and whitening:
            print("Whitening 1: {}".format(hexlify(self.k1)))
            print("Whitening 2: {}".format(hexlify(self.k2)))
            print("")

        self.mode = mode
        self.block_size = 8

    def encrypt(self, plaintext):
        ciphertext = ""
        blocks = split_by_blocks_padding(plaintext, self.block_size)

        for block in blocks:
            if VERBOSE:
                print("Block: {}".format(hexlify(block)))

            if self.k1 != None:
                block = xor(block, self.k1)
            
            block = feistel_network(block, 16, self.subkeys, operation=ENCRYPT)

            if self.k2 != None:
                block = xor(block, self.k2)

            ciphertext = ciphertext + ''.join(block)
            if VERBOSE:
                print("")

        return ciphertext

    def decrypt(self, ciphertext):
        decrypted = ""
        blocks = split_by_blocks(ciphertext, self.block_size)

        for block in blocks:
            if VERBOSE:
                print("Block: {}".format(hexlify(block)))

            if self.k2 != None:
                block = xor(block, self.k2)
            
            block = feistel_network(block, 16, self.subkeys, operation=DECRYPT)

            if self.k1 != None:
                block = xor(block, self.k1)

            decrypted = decrypted + ''.join(block)
            if VERBOSE:
                print("")

        return pkcs7_unpad(decrypted, self.block_size)


def pkcs7_pad(data, size):
    pad_len = size - (len(data) % size)
    return data.ljust(size, chr(pad_len))

def pkcs7_unpad(data, size):
    pad_len = ord(data[-1])
    return data[:-pad_len]


def gen_des_key(key):
    ''' returns key with parity '''
    
    if len(key) != 7:
        print("[WARN] Incorrect key size, it will be transformed")
        if len(key) > 7:
            key = key[:7]
        elif len(key) < 7:
            key = pkcs7_pad(key, 7)

    log = '|'
    key_parity = ''
    counter = 0
    parity = 0
    for bit in str_to_binary(key):
        log += bit
        key_parity += bit
        parity ^= int(bit)
        
        counter += 1
        
        if counter % 7 == 0:
            key_parity += bin(parity)[2:]
            log += ' ' + bin(parity)[2:] + '|'
            parity = 0
            
    if VERBOSE:
        print(log)

    return binary_to_str(key_parity)

def is_des_key(key):
    if len(key) != 8:
        return False
    
    parity = 0
    counter = 1
    for bit in str_to_binary(key):
        if counter % 8 == 0:
            if int(bit) != parity:
                print("[WARN] Key parity is invalid")
                return False
            parity = 0
            counter = 1
            continue

        parity ^= int(bit)
        counter += 1
    
    return True


def split_by_blocks_padding(data, block_size):
    block_count = len(data) // block_size
    blocks = split_by_blocks(data, block_size)

    last_block_size = len(data) - block_count * block_size

    if last_block_size:
        blocks.append(
            pkcs7_pad(
                data[block_count * block_size : ],
                block_size
                )
            )
    else:
        blocks.append(chr(block_size) * block_size)

    return blocks

def split_by_blocks(data, block_size):
    block_count = len(data) // block_size
    blocks = []

    for i in range(0, block_count * block_size, block_size):
        blocks.append(data[i:i + block_size])

    return blocks


def gen_subkeys(key, rounds):
    subkeys = []

    if VERBOSE:
        print("Subkeys:")

    key = permutation(key, PC_1)
    binary_key = str_to_binary(key)

    c = binary_key[:len(binary_key) // 2]
    d = binary_key[len(binary_key) // 2:]

    for i in range(rounds):
        c = shift_left(c, SHIFT[i])
        d = shift_left(d, SHIFT[i])

        subkeys.append(permutation(binary_to_str(c + d), PC_2))
        if VERBOSE:
            print("Round {} key: {}".format(i + 1, hexlify(subkeys[-1])))

    if VERBOSE:
        print("")

    return subkeys

def feistel_network(block, rounds, subkeys, operation=ENCRYPT):
    block = permutation(block, IP)

    l = block[:len(block) // 2]
    r = block[len(block) // 2:]
    
    if VERBOSE:
        print("{} | {}".format(hexlify(l), hexlify(r)))

    for round_i in range(rounds):
        tmp = r

        if operation == ENCRYPT:
            r = xor(round_function(r, subkeys[round_i]), l)
        else:
            r = xor(round_function(r, subkeys[15 - round_i]), l)
        l = tmp

        if VERBOSE:
            print("Round {}: {} | {}".format(str(round_i + 1).rjust(2, '0'), hexlify(''.join(l)), hexlify(''.join(r))))

    block = permutation(r + l, IP_1)
    return block

def round_function(block, subkey):

    block = expansion(block, E)
    block = xor(block, subkey)

    binary_block = str_to_binary(block)
    subblocks = split_by_blocks(binary_block, 6)

    binary_res = ''
    for i in range(len(subblocks)):
        subblock = subblocks[i]
        row = int(subblock[0] + subblock[5], base=2)
        column = int(subblock[1:5], base=2)
        binary_res += bin(S_BOX[i][row][column])[2:].rjust(4, '0')

    block = binary_to_str(binary_res)
    block = permutation(block, P)

    return block


def permutation(block, table):
    binary_block = str_to_binary(block)
    binary_block = [binary_block[x - 1] for x in table]
    return binary_to_str(''.join(binary_block))

def expansion(block, table):
    return permutation(block, table)

def xor(b1, b2):
    return [chr(ord(a) ^ ord(b)) for a, b in zip(b1, b2)]

def shift_left(value, n):
    return value[n:] + value[:n]


if __name__ == "__main__":
    plaintext = "Hello, world!"
    # plaintext = "Hello, w"
    print("Plaintext  : {}".format(plaintext))

    key_7b = "secret!"
    key = gen_des_key(key_7b)
    print("Key        : {} -> {}".format(key_7b, hexlify(key)))

    parity = is_des_key(key)
    print("Has parity : {}".format(parity))

    des = DES(key, ECB, whitening=False)
    ciphertext = des.encrypt(plaintext)
    print("Ciphertext : {}".format(hexlify(ciphertext)))

    decrypted = des.decrypt(ciphertext)
    print("Decrypted  : {}".format(decrypted))
    
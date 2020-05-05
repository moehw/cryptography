#!/usr/bin/env python3

import sys
import copy
import hashlib
import codecs
from Crypto.Util.number import bytes_to_long, long_to_bytes

sys.path.insert(1, './ecc')
sys.path.insert(1, '../ecc')
from ecdh import *

sys.path.insert(1, './finite-field')
sys.path.insert(1, '../finite-field')
from finitefield import *

from blockcipher import *


# Based on operations over GF(2**8) 
SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

R_SBOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

RC = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


class AES:
    def __init__(self, key, mode=ECB, iv=None):
        self.block_size = 16
        self.key = key
        if len(key) == (256 / 8):
            self.rounds = 14
        elif len(key) == (192 / 8):
            self.rounds = 12
        else:
            self.rounds = 10

        self.mode = mode
        if mode != ECB:
            print("[-] Mode is not implemented")

        self.iv = iv
        self.subkeys = gen_subkeys(key, self.rounds + 1)

    def encrypt(self, plaintext):
        ciphertext = b""
        blocks = split_by_blocks_padding(plaintext, self.block_size)
        
        for block in blocks:
            if VERBOSE:
                print("Block: {}".format(block))

            state = block_to_matrix(block)
            if VERBOSE:
                print_matrix(state)

            state = add_round_key(state, self.subkeys[0])
            if VERBOSE:
                print("After whitening (AddRoundKey):")
                print_matrix(state)

            for i in range(1, self.rounds + 1):
                if VERBOSE and i == 1:
                    print(f"Round {i}:")

                state = sub_byte(state, operation=ENCRYPT)
                if VERBOSE and i == 1:
                    print("After SubByte:")
                    print_matrix(state)

                state = shift_rows(state, operation=ENCRYPT)
                if VERBOSE and i == 1:
                    print("After ShiftRows:")
                    print_matrix(state)

                if i != self.rounds: # for last round
                    state = mix_columns(state, operation=ENCRYPT)
                    if VERBOSE and i == 1:
                        print("After MixColumns:")
                        print_matrix(state)

                state = add_round_key(state, self.subkeys[i])
                if VERBOSE and i == 1:
                    print("After AddRoundKey:")
                    print_matrix(state)

            block = matrix_to_block(state)

            ciphertext = ciphertext + block
            if VERBOSE:
                print("")

        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = b""

        blocks = split_by_blocks(ciphertext, self.block_size)
        
        for block in blocks:
            if VERBOSE:
                print("Block: {}".format(block))

            state = block_to_matrix(block)
            if VERBOSE:
                print_matrix(state)

            state = add_round_key(state, self.subkeys[10])
            if VERBOSE:
                print("After AddRoundKey:")
                print_matrix(state)

            for i in range(self.rounds - 1, -1, -1):
                if VERBOSE and i == (self.rounds - 1):
                    print(f"Round {self.rounds - i}:")

                state = shift_rows(state, operation=DECRYPT)
                if VERBOSE and i == (self.rounds - 1):
                    print("After inverse ShiftRows:")
                    print_matrix(state)

                state = sub_byte(state, operation=DECRYPT)
                if VERBOSE and i == (self.rounds - 1):
                    print("After inverse SubBute:")
                    print_matrix(state)

                state = add_round_key(state, self.subkeys[i])
                if VERBOSE and i == (self.rounds - 1):
                    print("After AddRoundKey:")
                    print_matrix(state)

                if i != 0:
                    state = mix_columns(state, operation=DECRYPT)
                    if VERBOSE and i == (self.rounds - 1):
                        print("After inverse MixColumns:")
                        print_matrix(state)

            block = matrix_to_block(state)

            plaintext = plaintext + block
            if VERBOSE:
                print("")

        return pkcs7_unpad(plaintext, self.block_size)


def print_matrix(state):
    for row in state:
        row_str = ''.join([(hex(i)[2:].rjust(2, '0') + ' ') for i in row])
        print(row_str)

def block_to_matrix(block):
    state = []
    for i in range(4): 
        row = [] 
        for j in range(i, 16, 4): 
            row.append(block[j])
        state.append(row)

    return state

def matrix_to_block(state):
    block = b""
    for i in range(4):
        for row in state:
            block += to_byte(row[i])
    return block


def word_rot(word):
    res = word[1:]
    res += to_byte(word[0])
    return res

def word_xor(word1, word2):
    word = b''
    for elem1, elem2 in zip(word1, word2):
        word += to_byte(elem1 ^ elem2)
    return word

def key_round(word, cur_round):
    word = word_rot(word)

    word_sub = b''
    for i in range(len(word)):
        word_sub += to_byte(SBOX[word[i]])
    
    word = to_byte(word_sub[0] ^ RC[cur_round]) + word_sub[1:]
           
    return word

def gen_subkeys(key, rounds):
    subkeys = []
    subkeys_matrix = []

    if VERBOSE:
        print("Key generate:")

    subkeys.append(split_by_blocks(key, 4))
    subkeys_matrix.append(block_to_matrix(key))
    key_words = len(subkeys[-1])

    if VERBOSE:
        print("Round key 0:")
        print_matrix(subkeys_matrix[-1])

    for i in range(1, rounds):
        subkey = []
        subkey.append(word_xor(subkeys[-1][0], key_round(subkeys[-1][key_words - 1], i)))

        for j in range(1, key_words):
            subkey.append(word_xor(subkeys[-1][j], subkey[-1]))

        subkeys.append(subkey)
        subkeys_matrix.append(block_to_matrix(join_blocks(subkey)))
        if VERBOSE:
            print("Round key {}:".format(i))
            print_matrix(subkeys_matrix[-1])

    if VERBOSE:
        print("")
        
    return subkeys_matrix


def add_round_key(state, subkey):
    matrix = []

    for row1, row2 in zip(state, subkey):
        row3 = []
        for elem1, elem2 in zip(row1, row2):
            row3.append(elem1 ^ elem2)
        matrix.append(row3)
    return matrix

def sub_byte(state, operation=ENCRYPT):
    for i in range(4):
        for j in range(4):
            if operation == ENCRYPT:
                state[i][j] = SBOX[state[i][j]]
            else:
                state[i][j] = R_SBOX[state[i][j]]
    return state
    
def shift_rows(state, operation=ENCRYPT):
    matrix = []
    if operation == ENCRYPT:
        for i in range(len(state)):
            matrix.append(state[i][i:] + state[i][:i])
    else:
        for i in range(len(state)):
            matrix.append(state[i][len(state) - i:] + state[i][:len(state) - i])
    return matrix

def gf_mult(byte1, byte2):
    p = 0b0100011011 # x^8 + x^4 + x^3 + x + 1 */
    return multiply_polynomials_over_gf(byte1, byte2, p)

def mix_columns(state, operation=ENCRYPT):
    res_state = copy.deepcopy(state)

    if operation == ENCRYPT:
        for i in range(4): 
            res_state[0][i] = (gf_mult(0x02, state[0][i]) ^ gf_mult(0x03, state[1][i]) ^ state[2][i] ^ state[3][i])
            res_state[1][i] = (state[0][i] ^ gf_mult(0x02, state[1][i]) ^ gf_mult(0x03, state[2][i]) ^ state[3][i])
            res_state[2][i] = (state[0][i] ^ state[1][i] ^ gf_mult(0x02, state[2][i]) ^ gf_mult(0x03, state[3][i]))
            res_state[3][i] = (gf_mult(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ gf_mult(0x02, state[3][i]))
    else:
        for i in range(4): 
            res_state[0][i] = (gf_mult(0x0E, state[0][i]) ^ gf_mult(0x0B, state[1][i]) ^ gf_mult(0x0D, state[2][i]) ^ gf_mult(0x09, state[3][i]))
            res_state[1][i] = (gf_mult(0x09, state[0][i]) ^ gf_mult(0x0E, state[1][i]) ^ gf_mult(0x0B, state[2][i]) ^ gf_mult(0x0D, state[3][i]))
            res_state[2][i] = (gf_mult(0x0D, state[0][i]) ^ gf_mult(0x09, state[1][i]) ^ gf_mult(0x0E, state[2][i]) ^ gf_mult(0x0B, state[3][i]))
            res_state[3][i] = (gf_mult(0x0B, state[0][i]) ^ gf_mult(0x0D, state[1][i]) ^ gf_mult(0x09, state[2][i]) ^ gf_mult(0x0E, state[3][i]))
            
    return res_state


if __name__ == "__main__":
    dh = ECDH(curve='secp128r1')

    d_a, e_a = dh.gen_key_pair()
    print("Alice's keys:")
    print("Private: {}".format(hex(d_a)))
    print("Public : {}, {}".format(hex(e_a[0]), hex(e_a[1])))
    print("")

    d_b, e_b = dh.gen_key_pair()
    print("Bob's keys:")
    print("Private: {}".format(hex(d_b)))   
    print("Public : {}, {}".format(hex(e_b[0]), hex(e_b[1])))
    print("")
    
    s_a = dh.point_mult_k(e_b, d_a)
    s_b = dh.point_mult_k(e_a, d_b)

    if s_a != s_b:
        print("[-] Secrets are different")
    else:
        print("Secret: {}, {}".format(hex(s_a[0]), hex(s_a[1])))

    key = byte_coord_to_sha1(s_a[0], 16)
    key = b"\xF1\x99\x93\xB5\x0B\x92\xA1\x9B\x05\x66\x7D\x9E\xEE\x0A\xEC\x56"
    print("Key (x with sha1): {}".format(key.hex()))
    iv = byte_coord_to_sha1(s_a[1], 16)

    aes = AES(key, ECB, iv)

    plaintext = b"Hello, world!"
    print("Plaintext: {}".format(plaintext))

    ciphertext = aes.encrypt(plaintext)
    print("Ciphertext: {}".format(ciphertext.hex()))

    decrypted = aes.decrypt(ciphertext)
    print("Decrypted : {}".format(decrypted))

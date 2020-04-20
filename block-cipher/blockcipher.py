#!/usr/bin/env python3

import codecs
from Crypto.Util.number import bytes_to_long, long_to_bytes

# VERBOSE = False
VERBOSE = True

ENCRYPT = 1
DECRYPT = 0

ECB = 0x00
CBC = 0x01
CTR = 0x10
OFB = 0x11

def str_to_binary(text):
    return ''.join(bin(ord(x))[2:].rjust(8, '0') for x in text)

def binary_to_str(binary):
    byte_count = len(binary) // 8

    string = str()
    for i in range(0, byte_count * 8, 8):
        byte = int(binary[i:i + 8], 2)
        string = string + chr(byte)
    return string

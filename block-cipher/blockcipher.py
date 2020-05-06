#!/usr/bin/env python3

import codecs

# VERBOSE = False
VERBOSE = True

ENCRYPT = 1
DECRYPT = 0

ECB = 0x00
CBC = 0x01
CTR = 0x10
OFB = 0x11


def hexlify(string):
    hex_string = ''
    for ch in string:
        hex_value = hex(ord(ch))[2:].rjust(2, '0')
        hex_string = hex_string + hex_value
    return hex_string


def pkcs7_pad(data, size):
    pad_len = size - (len(data) % size)
    if isinstance(data, bytes):
        data = data.ljust(size, to_byte(pad_len))
    else:
        data = data.ljust(size, chr(pad_len))
    return data

def pkcs7_unpad(data, size):
    if isinstance(data, bytes):
        pad_len = data[-1]
    else:
        pad_len = ord(data[-1])

    # check for valid padding
    for i in range(pad_len):
        if data[- (i + 1)] != data[-1]:
            print("[WARN] Invalid padding")
            break

    return data[:-pad_len] if pad_len <= len(data) else data


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
        blocks.append(pkcs7_pad(b'' if isinstance(data, bytes) else '', block_size))

    return blocks

def split_by_blocks(data, block_size):
    block_count = len(data) // block_size
    blocks = []

    for i in range(0, block_count * block_size, block_size):
        blocks.append(data[i:i + block_size])

    return blocks

def join_blocks(blocks):
    return b''.join([i for i in blocks])


def to_byte(integer):
    return integer.to_bytes(1, 'big')

def str_to_binary(text):
    return ''.join(bin(ord(x))[2:].rjust(8, '0') for x in text)

def binary_to_str(binary):
    byte_count = len(binary) // 8

    string = str()
    for i in range(0, byte_count * 8, 8):
        byte = int(binary[i:i + 8], 2)
        string = string + chr(byte)
    return string

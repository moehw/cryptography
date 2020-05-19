#!/usr/bin/env python3

import sys
import random
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes

from ecdh import *

sys.path.insert(1, '../finite-field')
sys.path.insert(1, './finite-field')
from finitefield import *

class ECDSA(ECDH):
    def get_hash(self, message):
        message_hash = hashlib.md5(message).digest()
        e = int.from_bytes(message_hash, 'big')

        # trim the length of hash, it it is greater than n
        if e.bit_length() >= self.n.bit_length():
            z = e >> (e.bit_length() - self.n.bit_length())
        else:
            z = e
        return z

    def sign(self, private_key, message):
        z = self.get_hash(message)

        r = 0
        s = 0

        while (not r) or (not s):
            k = random.randrange(1, self.n)
            x, y = self.point_mult_k(self.g, k)

            r = x % self.n
            s = ((z + r * private_key) * inv_mod(k, self.n)) % self.n

        return (r, s)

    def verify(self, public_key, message, signature):
        z = self.get_hash(message)

        r, s = signature

        w = inv_mod(s, self.n)
        u1 = (z * w) % self.n
        u2 = (r * w) % self.n

        x, y = self.point_add(self.point_mult_k(self.g, u1), self.point_mult_k(public_key, u2))

        if (r % self.n) == (x % self.n):
            return '[+] Correct signature'
        else:
            return '[-] Invalid signature'

if __name__ == "__main__":

    ec = ECDSA(curve='secp128r1')

    private_a, public_a = ec.gen_key_pair()
    print("Alice's keys:")
    print("Private: {}".format(hex(private_a)))
    print("Public : {}, {}".format(hex(public_a[0]), hex(public_a[1])))
    print("")

    message = b'Hello from Alice!'
    signature = ec.sign(private_a, message)

    print("Alice's message:", message.decode())
    print("Signature: ({}, {})".format(hex(signature[0]), hex(signature[1])))
    print("Verification:", ec.verify(public_a, message, signature))
    print("")

    eva_message = b'Hello from Eva!'

    print("Eva's message:", eva_message.decode())
    print("Verification:", ec.verify(public_a, eva_message, signature))

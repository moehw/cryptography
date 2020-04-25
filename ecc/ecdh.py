#!/usr/bin/env python3

import sys
import random
import hashlib

sys.path.insert(1, './finite-field')
from finitefield import *

# Weierstrass's elliptic curve
# Recommended 128-bit Elliptic Curve: secp128r1
# https://www.secg.org/SEC2-Ver-1.0.pdf

class ECDH:
    def __init__(self, curve='secp128r1', p=None, a=None, b=None, g=None, n=None, h=None):
        if curve == 'secp128r1':
            # ( p; a; b; G; n; h)
            self.p = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF # 2^128 - 2^97 - 1, characteristic of GF
            
            self.a = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC # coefficient a
            self.b = 0xE87579C11079F43DD824993C2CEE5ED3 # coefficient b
            
            self.s = 0x000E0D4D696E6768756151750CC03A4473D036 # seed
            
            self.g = (0x161FF7528B899B2D0C28607CA52C5B86, # base point
                      0xCF5AC8395BAFEB13C02DA292DDED7A83)

            self.n = 0xFFFFFFFE0000000075A30D1B9038A115 # subgroup order
            self.h = 0x01 # cofactor
        else:
            self.p = p
            self.a = a
            self.b = b
            self.g = g
            self.n = n
            self.h = h

    def is_point_on_curve(self, point):
        # None is inf
        if point is None:
            return True
        
        x, y = point
        # y**2 = x**3 + a*x + b
        return (pow(x, 3, self.p) + (self.a * x % self.p) + self.b - pow(y, 2, self.p)) % self.p == 0

    def point_negative(self, point):
        if point is None:
            return None

        x, y = point
        return (x, -y % self.p)

    def point_add(self, point1, point2):
        if point1 == None:
            return point2
        
        if point2 == None:
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 != y2:
            # each x has 2 points, so y1 == -y2 (y2 is a negative point)
            return None

        if point1 != point2:
            m = ((y2 - y1) * inv_mod((x2 - x1), self.p)) % self.p
        else:
            m = ((3 * pow(x1, 2, self.p) + self.a) * inv_mod((2 * y1), self.p)) % self.p

        # x3 = m**2 - x1 - x2
        x3 = (pow(m, 2, self.p) - x1 - x2) % self.p
        # -y3 = y1 - m * (x3 - x1)
        y3 = -(y1 + m * (x3 - x1)) % self.p

        return (x3, y3)

    def point_mult_naive(self, point, k):
        # SO SLOW, DO NOT USE IT
        res_point = point
        for _ in range(k):
            res_point = self.point_add(res_point, point)
        
        return res_point

    def point_mult_k(self, point, k):
        # if k % self.n == 0:
        #     return None
        
        res_point = None
        cur_power = point

        # decompose k into powers of two
        # k * P = (... + k2*2**2 + k1*2**1 + k0*2**0) * P =
        #       = ... + k2*2**2*P + k1*2**1*P + k0*2**0*P
        while k:
            if k & 1:
                res_point = self.point_add(res_point, cur_power)
            cur_power = self.point_add(cur_power, cur_power)
            k >>= 1

        return res_point

    def gen_key_pair(self, num=None):
        if num == None \
        or num <= 0 \
        or num >= self.n:
            d = random.randrange(1, self.n)
        else:
            d = num
            
        e = self.point_mult_k(self.g, d)
        return d, e

from six import int2byte, b

def int_to_string(x):
    """Convert integer x into a string of bytes, as per X9.62."""
    assert x >= 0
    if x == 0:
        return b("\0")
    result = []
    while x:
        ordinal = x & 0xFF
        result.append(int2byte(ordinal))
        x >>= 8
    result.reverse()
    return b("").join(result)

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

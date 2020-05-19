#!/usr/bin/env python3

import sys
import random
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes

sys.path.insert(1, '../finite-field')
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
        if point == (0, 0):
            return True
        
        x, y = point
        # y**2 = x**3 + a*x + b
        return (pow(x, 3, self.p) + (self.a * x % self.p) + self.b - pow(y, 2, self.p)) % self.p == 0

    def get_y_by_x(self, x):
        # Lagrange's formula:
        # https://en.wikipedia.org/wiki/Quadratic_residue#Prime_or_prime_power_modulus

        y_2 = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        if pow(y_2, (self.p - 1) // 2, self.p) == 1: # y**2 is a quadratic residue of p
            if self.p % 4 == 3:
                y = pow(y_2, (self.p + 1) // 4, self.p)
                if self.is_point_on_curve((x, y)):
                    return y, -y % self.p
            
            if self.p % 8 == 5:
                y = pow(y_2, (self.p + 3) // 8, self.p)
                if self.is_point_on_curve((x, y)):
                    return y, -y % self.p
        return None

    def point_negative(self, point):
        if point == (0, 0):
            return (0, 0)

        x, y = point
        return (x, -y % self.p)

    def point_add(self, point1, point2):
        if point1 == (0, 0):
            return point2
        
        if point2 == (0, 0):
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 != y2:
            # each x has 2 points, so y1 == -y2 (y2 is a negative point)
            return (0, 0)

        if point1 != point2:
            m = ((y1 - y2) * inv_mod((x1 - x2), self.p)) % self.p
        else:
            m = ((3 * pow(x1, 2, self.p) + self.a) * inv_mod((2 * y1), self.p)) % self.p

        # x3 = m**2 - x1 - x2
        x3 = (pow(m, 2, self.p) - x1 - x2) % self.p
        # y3 = y1 - m * (x3 - x1)
        y3 = y1 + m * (x3 - x1) % self.p

        # P + Q = -R
        return self.point_negative((x3, y3))

    def point_mult_naive(self, point, k):
        # SO SLOW, DO NOT USE IT
        res_point = point
        for _ in range(k):
            res_point = self.point_add(res_point, point)
        
        return res_point

    def point_mult_k(self, point, k):
        if (self.n is not None) and (k % self.n == 0):
            return (0, 0)
        
        res_point = (0, 0)
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


def str_coord_to_sha1(x, size):
    sha1 = hashlib.sha1()
    sha1.update(str(x).encode('ascii'))
    key = sha1.digest()[:size]
    return key

def byte_coord_to_sha1(x, size):
    sha1 = hashlib.sha1()
    sha1.update(long_to_bytes(x))
    key = sha1.digest()[:size]
    return key


### TEST

def TEST_mult_add():
    dh = ECDH(None, 97, 2, 3)
    p = (3, 6)
    assert(dh.point_mult_k(p, 0) == (0, 0))
    assert(dh.point_mult_k(p, 1) == (3, 6))
    assert(dh.point_mult_k(p, 2) == (80, 10))
    assert(dh.point_mult_k(p, 3) == (80, 87))
    assert(dh.point_mult_k(p, 4) == (3, 91))
    assert(dh.point_mult_k(p, 5) == (0, 0))

def TEST_gen_key():
    dh = ECDH(None, 9739, 497, 1768, (1804, 5368))
    q_a = (815, 3190)
    n_b = 1829
    p = dh.point_mult_k(q_a, n_b)
    assert(p == (7929, 707))

def TEST_gen_key_one_coord():
    dh = ECDH(None, 9739, 497, 1768, (1804, 5368))
    q_x = 4726
    n_b = 6534
    q_y1, q_y2 = dh.get_y_by_x(q_x)
    assert(q_y1 == 3452 or q_y1 == 6287)
    assert(q_y2 == 3452 or q_y2 == 6287)

    p1 = dh.point_mult_k((q_x, q_y1), n_b)
    p2 = dh.point_mult_k((q_x, q_y2), n_b)
    inv_p2 = (dh.point_negative(p2))
    assert(inv_p2 == p1)
    assert(p2[0] == p1[0])


if __name__ == "__main__":
    dh = ECDH(curve='secp128r1')

    d_a, e_a = dh.gen_key_pair()
    print("Alice's keys:")
    print("Private: {}".format(hex(d_a)))
    print("Public : {}, {}".format(hex(e_a[0]), hex(e_a[1])))

    d_b, e_b = dh.gen_key_pair()
    print("Bob's keys:")
    print("Private: {}".format(hex(d_b)))   
    print("Public : {}, {}".format(hex(e_b[0]), hex(e_b[1])))
    print("-" * 100)

    print(f"Alice's x coord: {hex(e_a[0])}")
    last_bit = int(bin(e_a[1])[-1])
    print(f"Alice's y last bit: {last_bit}")

    y1_a, y2_a = dh.get_y_by_x(e_a[0])
    print(f"y and -y for x: {hex(y1_a)} , {hex(y2_a)}")
    y_a = y1_a if ((y1_a & 0x01) == last_bit) else y2_a
    print(f"Alice's y: {hex(y_a)}")
    print("")
    s_b = dh.point_mult_k((e_a[0], y_a), d_b)

    print(f"Bob's x coord: {hex(e_b[0])}")
    last_bit = int(bin(e_b[1])[-1])
    print(f"Bob's y last bit: {last_bit}")

    y1_b, y2_b = dh.get_y_by_x(e_b[0])
    print(f"y and -y for x: {hex(y1_b)} , {hex(y2_b)}")
    y_b = y1_b if ((y1_b & 0x01) == last_bit) else y2_b
    print(f"Bob's y: {hex(y_b)}")
    print("")
    s_a = dh.point_mult_k((e_b[0], y_b), d_a)

    if s_a != s_b:
        print("[-] Secrets are different")
    else:
        print("Secret: {}, {}".format(hex(s_a[0]), hex(s_a[1])))

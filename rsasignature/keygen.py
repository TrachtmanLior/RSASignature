import random

def gcd(a, b):
    while b: a, b = b, a % b
    return a

def xgcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q*x1
        y0, y1 = y1, y0 - q*y1
    return a, x0, y0

def inverse(a, n):
    g, x, _ = xgcd(a, n)
    if g != 1:
        raise Exception("Inverse does not exist.")
    return x % n

def generate_large_prime(bits, primality_test):
    p = random.getrandbits(bits)
    p |= (1 << bits - 1) | 1
    while not primality_test(p):
        p += 2
    return p

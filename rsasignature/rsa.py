import random
from rsasignature.utils import exp, as_bytes
from rsasignature.keygen import generate_large_prime, gcd, inverse
from rsasignature.primality import miller_rabin

class RSA:
    def __init__(self, size=2048, primality_test="miller_rabin"):
        assert primality_test == "miller_rabin"
        self.bit_size = size
        self.primality_test = miller_rabin

        self.p = generate_large_prime(size, self.primality_test)
        self.q = generate_large_prime(size, self.primality_test)
        while self.p == self.q:
            self.q = generate_large_prime(size, self.primality_test)

        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.public_key, self.private_key = self.__generate_keys()

    def __generate_keys(self):
        e = random.randrange(2, self.phi)
        while gcd(e, self.phi) != 1:
            e = random.randrange(2, self.phi)
        d = inverse(e, self.phi)
        return (e, self.n), (d, self.n)

    @staticmethod
    def process_string(message):
        return int.from_bytes(as_bytes(message), 'big')

    @staticmethod
    def recover_string(number):
        return number.to_bytes((number.bit_length() + 7) // 8, 'big')

    def sign(self, message):
        d, n = self.private_key
        m = RSA.process_string(message) if isinstance(message, str) else message
        return exp(m, d, n)

    def verify(self, signature, public_key):
        e, n = public_key
        return exp(signature, e, n)

import random
import hashlib
from rsasignature.utils import exp, as_bytes
from rsasignature.keygen import generate_large_prime, gcd, inverse
from rsasignature.primality import miller_rabin

class RSA:
    # ASN.1 DigestInfo prefixes for different hash algorithms
    HASH_ASN1_PREFIX = {
        'SHA-224': bytes.fromhex('302d300d06096086480165030402040500041c'),
        'SHA-256': bytes.fromhex('3031300d060960864801650304020105000420'),
        'SHA-384': bytes.fromhex('3041300d060960864801650304020205000430'),
        'SHA-512': bytes.fromhex('3051300d060960864801650304020305000440'),
        'SHA224': bytes.fromhex('302d300d06096086480165030402040500041c'),
        'SHA256': bytes.fromhex('3031300d060960864801650304020105000420'),
        'SHA384': bytes.fromhex('3041300d060960864801650304020205000430'),
        'SHA512': bytes.fromhex('3051300d060960864801650304020305000440'),
    }
    
    def __init__(self, size=2048, primality_test="miller_rabin"):
        assert primality_test == "miller_rabin"
        self.bit_size = size
        self.primality_test = miller_rabin

        self.p = generate_large_prime(size // 2, self.primality_test)
        self.q = generate_large_prime(size // 2, self.primality_test)
        while self.p == self.q:
            self.q = generate_large_prime(size // 2, self.primality_test)

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

    def _hash_message(self, message, hash_alg='SHA-256'):
        """Hash the message using the specified algorithm."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        elif isinstance(message, int):
            # Convert integer to bytes for hashing
            message = message.to_bytes((message.bit_length() + 7) // 8, 'big')
        
        hash_alg_normalized = hash_alg.upper().replace('-', '')
        
        if hash_alg_normalized == 'SHA224':
            h = hashlib.sha224(message)
        elif hash_alg_normalized == 'SHA256':
            h = hashlib.sha256(message)
        elif hash_alg_normalized == 'SHA384':
            h = hashlib.sha384(message)
        elif hash_alg_normalized == 'SHA512':
            h = hashlib.sha512(message)
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_alg}")
        
        return h.digest()

    def _pkcs1_v15_pad(self, message, hash_alg='SHA-256'):
        """Apply PKCS#1 v1.5 padding to the message."""
        # Get the modulus size in bytes
        k = (self.n.bit_length() + 7) // 8
        
        # Hash the message
        h = self._hash_message(message, hash_alg)
        
        # Get the ASN.1 prefix for this hash algorithm
        if hash_alg not in self.HASH_ASN1_PREFIX:
            raise ValueError(f"Unsupported hash algorithm: {hash_alg}")
        
        digest_info = self.HASH_ASN1_PREFIX[hash_alg] + h
        
        # Calculate padding length
        padding_len = k - len(digest_info) - 3
        
        if padding_len < 8:
            raise ValueError("Message too long for key size")
        
        # Construct the padded message: 0x00 || 0x01 || PS || 0x00 || DigestInfo
        # PS is padding string of 0xFF bytes
        padded = b'\x00\x01' + (b'\xff' * padding_len) + b'\x00' + digest_info
        
        return padded

    def sign(self, message, hash_alg='SHA-256'):
        """Sign a message using PKCS#1 v1.5."""
        d, n = self.private_key
        
        # Apply PKCS#1 v1.5 padding
        padded = self._pkcs1_v15_pad(message, hash_alg)
        
        # Convert padded message to integer
        m = int.from_bytes(padded, 'big')
        
        # Sign
        return exp(m, d, n)

    def verify(self, signature, public_key, message=None, hash_alg='SHA-256'):
        """Verify a PKCS#1 v1.5 signature."""
        e, n = public_key
        
        # Decrypt the signature
        decrypted = exp(signature, e, n)
        
        # Convert to bytes with proper length
        k = (n.bit_length() + 7) // 8
        decrypted_bytes = decrypted.to_bytes(k, 'big')
        
        if message is None:
            # Just return the decrypted value (for backward compatibility)
            return decrypted
        
        # Verify PKCS#1 v1.5 padding and compare with expected
        try:
            expected_padded = self._pkcs1_v15_pad(message, hash_alg)
            return decrypted_bytes == expected_padded
        except:
            return False

    def sign_raw(self, message):
        """Sign a message without padding (textbook RSA)."""
        d, n = self.private_key
        m = RSA.process_string(message) if isinstance(message, str) else message
        return exp(m, d, n)

    def verify_raw(self, signature, public_key):
        """Verify a signature without padding (textbook RSA)."""
        e, n = public_key
        return exp(signature, e, n)
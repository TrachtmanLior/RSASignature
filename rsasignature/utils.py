def exp(x, n, p):
    """
    Calculate x to the power of n, modulo p.
    :param x: base
    :param n: exponent
    :param p: modulus
    :return: x^n % p
    """
    result = 1
    x = x % p
    while n > 0:
        if n % 2 == 1:
            result = (result * x) % p
        x = (x * x) % p
        n //= 2
    return result

def as_bytes(msg):
    """
    Convert a string or bytes object to bytes.
    :param msg: string or bytes object
    :return: bytes
    """
    return bytes(msg, 'utf-8') if isinstance(msg, str) else msg


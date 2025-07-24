def exp(x, n, p):
    result = 1
    x = x % p
    while n > 0:
        if n % 2 == 1:
            result = (result * x) % p
        x = (x * x) % p
        n //= 2
    return result

def as_bytes(msg):
    return bytes(msg, 'utf-8') if isinstance(msg, str) else msg

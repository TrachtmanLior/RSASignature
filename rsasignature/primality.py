import random
def miller_rabin(n, k=40):
    """
    Perform the Miller-Rabin primality test on a given number.

    Args:
        n (int): The number to be tested for primality.
        k (int, optional): The number of accuracy rounds. Default is 40.

    Returns:
        bool: True if `n` is probably prime, False if it is composite.
    """

    # If number is even, it's a composite number
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    # Write (n - 1) as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

import secrets


def is_probable_prime(n, rounds=20):
    # Numbers below 2 are not prime
    if n < 2:
        return False

    # Check small prime divisors
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n - 1 as d * 2^s
    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    # Miller-Rabin test
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits):
    while True:
        # Generate a random number with the required bit length
        n = secrets.randbits(bits)

        # Make sure it has the correct length and is odd
        n |= (1 << (bits - 1))
        n |= 1

        if is_probable_prime(n):
            return n

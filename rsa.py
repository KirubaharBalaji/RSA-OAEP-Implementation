from math import gcd
from primes import generate_prime


def generate_keypair(bits=2048):
    e = 65537

    # Generate two different prime numbers
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits - bits // 2)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        # Check if e can be used
        if gcd(e, phi) == 1:
            break

    # Calculate the private exponent
    d = pow(e, -1, phi)

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


def encrypt_int(message, public_key):
    n, e = public_key

    if not isinstance(message, int) or isinstance(message, bool):
        raise TypeError("Message must be an integer")

    if message < 0 or message >= n:
        raise ValueError("Message must be between 0 and n - 1")

    return pow(message, e, n)


def decrypt_int(ciphertext, private_key):
    n, d = private_key

    if not isinstance(ciphertext, int) or isinstance(ciphertext, bool):
        raise TypeError("Ciphertext must be an integer")

    if ciphertext < 0 or ciphertext >= n:
        raise ValueError("Ciphertext must be between 0 and n - 1")

    return pow(ciphertext, d, n)

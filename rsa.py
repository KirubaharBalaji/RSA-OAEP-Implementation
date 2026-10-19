from math import gcd
from primes import generate_prime


def generate_keypair(bits, e):
    """Generate RSA public and private keys."""

    # Validate the key size.
    if not isinstance(bits, int) or isinstance(bits, bool):
        raise TypeError("Key size must be an integer")

    if bits < 2048:
        raise ValueError("Key size must be at least 2048 bits")

    # Validate the public exponent.
    if not isinstance(e, int) or isinstance(e, bool):
        raise TypeError("Public exponent must be an integer")

    if e < 3:
        raise ValueError("Public exponent must be at least 3")

    if e % 2 == 0:
        raise ValueError("Public exponent must be odd")

    # Generate two different prime numbers.
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits - bits // 2)

        if p == q:
            continue

        n = p * q

        # Ensure the modulus has the requested bit length.
        if n.bit_length() != bits:
            continue

        # Calculate Euler's totient.
        phi = (p - 1) * (q - 1)

        # Check whether e is suitable for these primes.
        if e >= phi:
            raise ValueError("Public exponent must be smaller than phi(n)")

        if gcd(e, phi) != 1:
            continue

        # Calculate the private exponent.
        d = pow(e, -1, phi)

        public_key = (n, e)
        private_key = (n, d)

        return public_key, private_key


def encrypt_int(message, public_key):
    """Encrypt an integer using the RSA public key."""

    n, e = public_key

    if not isinstance(message, int) or isinstance(message, bool):
        raise TypeError("Message must be an integer")

    if message < 0 or message >= n:
        raise ValueError("Message must be between 0 and n - 1")

    return pow(message, e, n)


def decrypt_int(ciphertext, private_key):
    """Decrypt an integer using the RSA private key."""

    n, d = private_key

    if not isinstance(ciphertext, int) or isinstance(ciphertext, bool):
        raise TypeError("Ciphertext must be an integer")

    if ciphertext < 0 or ciphertext >= n:
        raise ValueError("Ciphertext must be between 0 and n - 1")

    return pow(ciphertext, d, n)

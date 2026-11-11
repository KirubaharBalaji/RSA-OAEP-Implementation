
import secrets


def is_probable_prime(n, rounds=40):
    """Check whether n is probably prime using the Miller-Rabin test."""

    # Validate the input number.
    if not isinstance(n, int) or isinstance(n, bool):
        raise TypeError("Input number must be an integer")

    # Validate the number of Miller-Rabin rounds.
    if not isinstance(rounds, int) or isinstance(rounds, bool):
        raise TypeError("Rounds must be an integer")

    if rounds <= 0:
        raise ValueError("Rounds must be a positive integer")

    # Handle small numbers.
    if n < 2:
        return False

    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    # Write n - 1 as d * 2^s.
    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    # Perform the Miller-Rabin rounds.
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
    """Generate a probable prime with the requested bit length."""

    if not isinstance(bits, int) or isinstance(bits, bool):
        raise TypeError("Bit length must be an integer")

    if bits < 2:
        raise ValueError("Bit length must be at least 2")

    while True:
        # Generate a random number with exactly the requested bit length.
        candidate = secrets.randbits(bits)

        # Set the highest bit and lowest bit.
        candidate |= (1 << (bits - 1))
        candidate |= 1

        if is_probable_prime(candidate):
            return candidate

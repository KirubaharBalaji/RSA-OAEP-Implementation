import secrets


def generate_small_primes(limit=1000):
    """Generate all prime numbers up to the given limit."""

    if limit < 2:
        return ()

    numbers = [True] * (limit + 1)
    numbers[0] = numbers[1] = False

    for i in range(2, int(limit ** 0.5) + 1):
        if numbers[i]:
            for j in range(i * i, limit + 1, i):
                numbers[j] = False

    return tuple(
        i for i in range(2, limit + 1) if numbers[i]
    )


def is_probable_prime(n, rounds=40):
    """Check whether n is probably prime using Miller-Rabin."""

    if n < 2:
        return False

    if rounds < 1:
        raise ValueError("Rounds must be at least 1")

    # Check divisibility using dynamically generated small primes.
    for p in generate_small_primes(1000):
        if n == p:
            return True

        if n % p == 0:
            return False

    # Express n - 1 as d * 2^s.
    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    # Perform Miller-Rabin testing.
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
    """Generate a probable prime with exactly 'bits' bits."""

    if not isinstance(bits, int) or isinstance(bits, bool):
        raise TypeError("Bits must be an integer")

    if bits < 2:
        raise ValueError("Bits must be at least 2")

    while True:
        # Generate a random number of the required bit length.
        n = secrets.randbits(bits)

        # Set the highest bit and make the number odd.
        n |= (1 << (bits - 1))
        n |= 1

        if is_probable_prime(n):
            return n

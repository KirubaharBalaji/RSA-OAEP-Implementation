
import statistics
import time

from rsa import generate_keypair, encrypt_int, decrypt_int


def measure_key_generation(bits, trials=5):
    times = []

    for _ in range(trials):
        start = time.perf_counter()
        public_key, private_key = generate_keypair(bits, 65537)
        end = time.perf_counter()

        times.append(end - start)

    return statistics.mean(times), statistics.median(times)


def measure_encryption_decryption(bits, trials=100):
    public_key, private_key = generate_keypair(bits, 65537)

    message = 12345
    ciphertext = encrypt_int(message, public_key)

    encryption_times = []
    decryption_times = []

    for _ in range(trials):
        start = time.perf_counter()
        ciphertext = encrypt_int(message, public_key)
        end = time.perf_counter()
        encryption_times.append(end - start)

        start = time.perf_counter()
        decrypted = decrypt_int(ciphertext, private_key)
        end = time.perf_counter()
        decryption_times.append(end - start)

        assert decrypted == message

    return (
        statistics.mean(encryption_times),
        statistics.median(encryption_times),
        statistics.mean(decryption_times),
        statistics.median(decryption_times),
    )


def main():
    for bits in [2048, 3072]:
        print(f"\nRSA {bits}-bit benchmark")

        key_mean, key_median = measure_key_generation(bits)
        print(f"Key generation average: {key_mean:.6f} seconds")
        print(f"Key generation median:  {key_median:.6f} seconds")

        enc_mean, enc_median, dec_mean, dec_median = (
            measure_encryption_decryption(bits)
        )

        print(f"Encryption average:     {enc_mean:.8f} seconds")
        print(f"Encryption median:      {enc_median:.8f} seconds")
        print(f"Decryption average:     {dec_mean:.8f} seconds")
        print(f"Decryption median:      {dec_median:.8f} seconds")


if __name__ == "__main__":
    main()

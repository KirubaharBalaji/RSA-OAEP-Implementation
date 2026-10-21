# RSA-OAEP Encryption and Decryption in Python

A Python implementation of RSA public-key encryption integrated with OAEP (Optimal Asymmetric Encryption Padding). The project separates RSA operations, OAEP encoding/decoding, prime generation, and byte/integer conversion into individual modules, with `main.py` providing the integration layer.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Algorithm Overview](#algorithm-overview)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Key Implementation Details](#key-implementation-details)
- [Notes](#notes)
- [Testing](#testing)



## Overview

RSA is an asymmetric cryptographic algorithm that uses a public key and a private key. OAEP adds randomized encoding before RSA encryption, helping make encryption probabilistic: encrypting the same message more than once can produce different ciphertexts.

This project implements the following components:

- RSA key-pair generation and integer encryption/decryption.
- OAEP encoding and decoding using SHA-256 and MGF1.
- Probable-prime generation using Miller–Rabin testing.
- Conversion between UTF-8 strings, bytes, and integers.

## Features

- **RSA key generation:** Configurable modulus size, with a minimum of 2048 bits in this implementation.
- **RSA integer operations:** Public-key encryption and private-key decryption of integer representatives.
- **OAEP padding:** Randomized encoding and padding validation.
- **SHA-256 and MGF1:** SHA-256 is used for the OAEP label hash and mask generation.
- **String and raw-byte support:** UTF-8 string functions and byte-oriented functions are available.
- **Byte/integer conversions:** Big-endian conversion helpers, including fixed-length integer-to-byte conversion to preserve leading zero bytes.
- **Optional OAEP label:** Supports a byte-string label that must match during encryption and decryption.
- **Input validation:** Checks key sizes, exponent constraints, integer ranges, and invalid OAEP encoding conditions.
- **Randomized encryption:** OAEP uses a random seed, so encrypting the same plaintext repeatedly should normally produce different ciphertexts.

## How It Works

### Encryption flow

1. Convert a plaintext string to UTF-8 bytes (for `encrypt`).
2. OAEP-encode the plaintext bytes using SHA-256 and MGF1.
3. Convert the OAEP-encoded byte sequence to an integer.
4. Encrypt the integer with the RSA public key.
5. Return the ciphertext as an integer.

### Decryption flow

1. Decrypt the ciphertext integer with the RSA private key.
2. Convert the resulting integer back to a fixed-length byte sequence based on the RSA modulus size.
3. OAEP-decode the byte sequence and validate the label hash and padding structure.
4. Return the original plaintext as a UTF-8 string or bytes.

```
Plaintext string
      |
      v
UTF-8 bytes
      |
      v
OAEP encoding (SHA-256 + MGF1)
      |
      v
Encoded bytes -> integer
      |
      v
RSA encryption with public key
      |
      v
Ciphertext integer
      |
      v
RSA decryption with private key
      |
      v
Integer -> fixed-length encoded bytes
      |
      v
OAEP decoding
      |
      v
Original plaintext bytes -> UTF-8 string (if requested)
```

## Algorithm Overview

### 1. RSA key generation

1. Generate two distinct probable primes, `p` and `q`.
2. Calculate the modulus: `n = p × q`.
3. Calculate Euler's totient: `φ(n) = (p − 1)(q − 1)`.
4. Check that public exponent `e` is odd, at least 3, smaller than `φ(n)`, and coprime to `φ(n)`.
5. Calculate the private exponent: `d = e⁻¹ mod φ(n)`.
6. Return public key `(n, e)` and private key `(n, d)`.

The integration layer defaults to `e = 65537`; the RSA module requires a modulus size of at least 2048 bits.

### 2. Prime generation and Miller–Rabin

1. Generate a random candidate with the requested bit length.
2. Set its highest bit and make it odd.
3. Reject candidates divisible by generated small primes up to 1000.
4. Apply the Miller–Rabin probable-prime test (40 rounds by default).
5. Return a candidate that passes the test.

Miller–Rabin is probabilistic: a passing candidate is considered probably prime.

### 3. OAEP encoding

The implementation uses SHA-256, so `hLen = 32` bytes.

1. Hash the optional label: `lHash = SHA-256(label)`.
2. Build `DB = lHash || PS || 0x01 || message`, where `PS` is zero padding sized to fit.
3. Generate a random seed of `hLen` bytes.
4. Generate `dbMask = MGF1(seed, k − hLen − 1)` and XOR it with `DB` to produce `maskedDB`.
5. Generate `seedMask = MGF1(maskedDB, hLen)` and XOR it with the seed to produce `maskedSeed`.
6. Construct `EM = 0x00 || maskedSeed || maskedDB`.

Here, `k` is the RSA modulus length in bytes. The maximum message length is `k − 2hLen − 2` bytes.

### 4. MGF1 with SHA-256

1. Append a 4-byte big-endian counter to the seed.
2. Hash `seed || counter` with SHA-256 for each counter value.
3. Concatenate hash outputs until enough mask bytes are generated.
4. Return exactly the requested number of bytes.

### 5. RSA encryption and decryption

The OAEP-encoded bytes are converted to a big-endian integer `m`.

- **Encryption:** `c = m^e mod n`
- **Decryption:** `m = c^d mod n`

The decrypted integer is converted back to exactly `k` bytes before OAEP decoding, preserving leading zero bytes.

### 6. OAEP decoding

1. Check the minimum encoded length and leading `0x00` byte.
2. Split the encoding into `maskedSeed` and `maskedDB`.
3. Regenerate masks and recover the seed and data block using XOR.
4. Recompute and compare the label hash.
5. Validate zero padding and locate the `0x01` separator.
6. Return the bytes after the separator.

Invalid padding or a mismatched label raises a `ValueError`.

## Project Structure

```
.
├── main.py             # Public integration API and example entry point
├── benchmark_rsa.py    # Benchmark Test for RSA Algorithm
├── rsa.py              # RSA key generation and integer operations
├── oaep.py             # OAEP encoding/decoding and MGF1
├── primes.py            # Prime generation and Miller–Rabin test
├── byte_conversion.py  # String/byte/integer conversion helpers
└── README.md
```

Keep these files in the same directory because `main.py` imports the other modules by their filenames.

## Requirements

- Python 3.12 or later recommended (the code uses modern type hints such as `str | bytes`).
- No third-party packages are required by the five supplied implementation files; they use Python standard-library modules.

## Installation

1. Install Python if it is not already installed.
2. Clone or download this repository.
3. Open a terminal in the project directory.
4. Confirm that all five `.py` files are in the same directory.

Check your Python version:

```
python --version
```

On some systems, use `python3` instead of `python`.

## Usage

### Run the interactive example

Run:

```
python main.py
```

The current `main.py` example generates a 2048-bit RSA key pair, prompts for a message, encrypts it, decrypts it, and prints the original message, ciphertext integer, recovered message, and whether the round trip succeeded.

Key generation can take some time because it generates probable primes.

## Key Implementation Details

- **OAEP hash:** SHA-256.
- **Mask generation:** MGF1 implemented with SHA-256.
- **Randomness:** OAEP seeds and prime candidates use Python's `secrets` module.
- **Prime testing:** Miller–Rabin probable-prime test with 40 rounds by default.
- **Default public exponent:** `65537`.
- **Default example key size:** 2048 bits.
- **Ciphertext representation:** integer, rather than a hexadecimal or byte string.
- **OAEP label:** optional bytes; the default is an empty label (`b""`).

## Notes

- **Keep module files together:** `main.py` imports `oaep.py`, `rsa.py`, and `byte_conversion.py`; `rsa.py` imports `primes.py`.
- **Use matching keys:** Encrypt with the public key and decrypt with its corresponding private key.
- **Use the same OAEP label:** A non-empty label supplied during encryption must be supplied unchanged during decryption.
- **Observe the message-size limit:** With SHA-256 and a 2048-bit RSA modulus, the maximum OAEP plaintext size is 190 bytes. Longer data should use a suitable hybrid-encryption design rather than direct RSA-OAEP encryption.
- **Ciphertexts are integers:** Define a consistent serialization format if storing or transmitting ciphertexts.
- **Preserve leading zeros:** Convert the decrypted integer to the modulus-sized byte length before OAEP decoding.
- **Encryption is randomized:** A fresh OAEP seed means identical messages normally produce different ciphertexts.
- **Private-key handling:** The project returns private-key components as an integer tuple and does not implement secure key storage.
- **Educational use:** This implementation has not been independently audited. Use a vetted cryptographic library for production applications.

## Testing

For a `pytest` test suite:

Installation
```
python -m pip install pytest
```

Verification
```
python -m pytest --version
```

Testing
```
python -m pytest -v test_main.py
```

Useful integration test cases include:

- Normal ASCII text.
- Unicode text, including accented characters and emoji.
- Empty messages.
- Raw bytes containing leading zero bytes.
- Conversion round trips with fixed byte lengths.
- Repeated encryption of the same message (ciphertexts should normally differ because OAEP uses a random seed).
- Incorrect OAEP label.
- Modified or invalid ciphertext.
- Invalid ciphertext length/range.
- Message exceeding the OAEP maximum length.
- Key sizes supported by the implementation, such as 2048 and 3072 bits.

## Disclaimer

This project is intended for educational and academic use. It demonstrates cryptographic concepts and is not a substitute for a vetted cryptographic library in production systems.

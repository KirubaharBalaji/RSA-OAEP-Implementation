# RSA-OAEP Encryption and Decryption in Python

A Python implementation of RSA public-key encryption integrated with OAEP (Optimal Asymmetric Encryption Padding). The project separates RSA operations, OAEP encoding and decoding, prime generation, and byte/integer conversion into individual modules, with `main.py` providing the integration layer.

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
- [Benchmarking](#benchmarking)
- [Testing](#testing)
- [Reference](#reference)
- [Disclaimer](#disclaimer)

## Overview

RSA is an asymmetric cryptographic algorithm that uses a public key and a private key. OAEP adds randomized encoding before RSA encryption, making encryption probabilistic: encrypting the same message more than once can produce different ciphertexts.

This project implements:

- RSA key-pair generation and integer encryption/decryption.
- OAEP encoding and decoding using SHA-256 and MGF1.
- Probable-prime generation using Miller–Rabin testing.
- Conversion between UTF-8 strings, bytes, and integers.

## Features

- **RSA key generation:** Configurable modulus size, with a minimum of 2048 bits in this implementation.
- **RSA integer operations:** Public-key encryption and private-key decryption of integer representatives.
- **OAEP padding:** Randomized encoding and validation of the recovered padding structure.
- **SHA-256 and MGF1:** SHA-256 is used for the OAEP label hash and mask generation.
- **String and raw-byte support:** Separate interfaces for UTF-8 text and binary data.
- **Byte/integer conversions:** Big-endian conversion helpers, including fixed-length integer-to-byte conversion to preserve leading zero bytes.
- **Optional OAEP label:** Supports a byte-string label that must match during encryption and decryption.
- **Input validation:** Checks key sizes, exponent constraints, integer ranges, and invalid OAEP encodings.
- **Randomized encryption:** OAEP uses a fresh random seed, so repeated encryption of the same plaintext normally produces different ciphertexts.
- **Automated tests:** Component-level, public-interface, and integration tests.
- **Performance benchmark:** Measures RSA key generation and integer encryption/decryption for 2048-bit and 3072-bit keys.
- **Makefile:** Provides installation, syntax-checking, execution, testing, and benchmarking commands.

## How It Works

### Encryption flow

1. Convert a plaintext string to UTF-8 bytes when using `encrypt()`.
2. OAEP-encode the plaintext bytes using SHA-256 and MGF1.
3. Convert the OAEP-encoded byte sequence to an integer.
4. Encrypt the integer with the RSA public key.
5. Return the ciphertext as an integer.

### Decryption flow

1. Decrypt the ciphertext integer with the RSA private key.
2. Convert the recovered integer to a fixed-length byte sequence matching the RSA modulus length.
3. OAEP-decode the byte sequence and validate the label hash and padding structure.
4. Return the plaintext as a UTF-8 string or raw bytes.

```text
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

The byte-oriented functions skip UTF-8 conversion and operate directly on plaintext bytes.

## Algorithm Overview

### 1. RSA key generation

1. Generate two distinct probable primes, `p` and `q`.
2. Calculate the modulus: `n = p × q`.
3. Calculate Euler's totient: `φ(n) = (p − 1)(q − 1)`.
4. Check that the public exponent `e` is odd, at least 3, smaller than `φ(n)`, and coprime to `φ(n)`.
5. Calculate the private exponent: `d = e⁻¹ mod φ(n)`.
6. Return the public key `(n, e)` and private key `(n, d)`.

The integration layer defaults to `e = 65537`. The RSA module requires a modulus size of at least 2048 bits.

### 2. Prime generation and Miller–Rabin

1. Generate a random candidate with the requested bit length.
2. Set the highest bit to preserve the requested bit length and the lowest bit to make the candidate odd.
3. Apply the Miller–Rabin probable-prime test, using 40 rounds by default.
4. Return the candidate if it passes; otherwise, generate another candidate.

The implementation does not use a small-prime sieve. Miller–Rabin is probabilistic, so a passing candidate is considered probably prime.

### 3. OAEP encoding

The implementation uses SHA-256, so `hLen = 32` bytes.

1. Hash the optional label: `lHash = SHA-256(label)`.
2. Build `DB = lHash || PS || 0x01 || message`, where `PS` is zero padding sized to fit.
3. Generate a random seed of `hLen` bytes.
4. Generate `dbMask = MGF1(seed, k − hLen − 1)` and XOR it with `DB` to produce `maskedDB`.
5. Generate `seedMask = MGF1(maskedDB, hLen)` and XOR it with the seed to produce `maskedSeed`.
6. Construct `EM = 0x00 || maskedSeed || maskedDB`.

Here, `||` denotes concatenation and `k` is the RSA modulus length in bytes. The maximum message length is `k − 2hLen − 2` bytes.

### 4. MGF1 with SHA-256

1. Start a counter at zero.
2. Encode each counter value as four big-endian bytes.
3. Hash `seed || counter` with SHA-256.
4. Concatenate successive hash outputs until enough mask bytes have been generated.
5. Return exactly the requested number of bytes.

### 5. RSA encryption and decryption

The OAEP-encoded bytes are converted to a big-endian integer `m`.

- **Encryption:** `c = m^e mod n`
- **Decryption:** `m = c^d mod n`

The decrypted integer is converted back to exactly `k` bytes before OAEP decoding. This restores the leading zero bytes required by the encoded message structure.

### 6. OAEP decoding

1. Check the minimum encoded length and leading `0x00` byte.
2. Split the encoding into `maskedSeed` and `maskedDB`.
3. Regenerate the masks and recover the seed and data block using XOR.
4. Recompute and compare the label hash.
5. Validate the zero padding and locate the `0x01` separator.
6. Return the bytes after the separator.

Invalid padding or a mismatched label raises a `ValueError`.

## Project Structure

```text
.
├── Makefile                 # Installation, syntax check, run, test and benchmark targets
├── requirements.txt         # Third-party test dependency
├── README.md                # Project documentation
├── main.py                  # Public integration layer and interactive demonstration
├── rsa.py                   # RSA key generation and integer operations
├── oaep.py                  # OAEP encoding, decoding and MGF1
├── primes.py                # Prime generation and Miller–Rabin test
├── byte_conversion.py       # String, byte and integer conversion helpers
├── benchmark_rsa.py         # RSA performance benchmark
└── tests/
    ├── test_primes.py       # Prime-generation tests
    ├── test_rsa.py          # RSA operation tests
    ├── test_oaep.py         # OAEP and MGF1 tests
    ├── test_main.py         # Public-interface tests
    └── test_integration.py  # Integration tests for both key sizes
```

Keep the implementation modules in the project root because the imports use their filenames. All five test modules belong inside `tests/`.

Run the documented commands from the project root, which contains `main.py`.

## Requirements

- **Python 3.10 or later.**
- **pytest** for automated testing, listed in `requirements.txt`.
- **Make** only when using the Makefile commands.

The implementation and benchmark use Python's standard library. No third-party cryptographic library is required.

Modules such as `hashlib` and `secrets` are included with Python and do not need separate installation.

The test dependency in `requirements.txt` is:

```text
pytest>=7.0
```

## Installation

1. Install Python 3.10 or later.
2. Clone or extract the repository.
3. Open a terminal in the project root.
4. Check the Python version and install the test dependency:

```bash
python --version
python -m pip install -r requirements.txt
```

### Syntax check

Check the implementation and benchmark files for Python syntax errors:

```bash
python -m py_compile main.py rsa.py primes.py oaep.py byte_conversion.py benchmark_rsa.py
```

Python source files run directly with the interpreter. This syntax check does not create a standalone executable.

### Makefile commands

When Make is installed, the following commands are available:

| Command | Purpose |
|---------|---------|
| `make help` | List available targets |
| `make install` | Install the test dependency |
| `make build` | Check the implementation and benchmark syntax |
| `make run` | Run the interactive demonstration |
| `make test` | Run all supplied tests |
| `make benchmark` | Run the RSA benchmark |

For example:

```bash
make install
make build
```

On systems where Python 3 is invoked as `python3`, replace `python` with `python3` in the direct commands. For Makefile commands, specify the interpreter:

```bash
make install PYTHON=python3
make build PYTHON=python3
```

Make is optional for execution. The direct Python commands can be used on systems where Make is unavailable.

## Usage

### Run the interactive example

From the project root:

```bash
python main.py
```

Alternatively:

```bash
make run
```

The demonstration generates a 2048-bit RSA key pair, prompts for a message, encrypts it, decrypts it, and prints:

- The original message.
- The ciphertext integer.
- The recovered message.
- Whether the recovered message matches the original.

Key-generation time varies because probable primes are generated randomly.

With the default 2048-bit key and SHA-256, the message must not exceed 190 UTF-8 bytes. This is a byte limit, not a character limit. Oversized messages are rejected.

### Public interface

The following functions are available in `main.py`:

| Function | Purpose |
|----------|---------|
| `generate_keys(bits=2048, e=65537)` | Generate the public and private keys |
| `encrypt(message, public_key, label=b"")` | Encrypt a UTF-8 string and return an integer ciphertext |
| `decrypt(ciphertext, private_key, label=b"", output_bytes=False)` | Decrypt to a UTF-8 string, or return bytes when requested |
| `encrypt_bytes(message, public_key, label=b"")` | Encrypt raw bytes |
| `decrypt_bytes(ciphertext, private_key, label=b"")` | Decrypt to raw bytes |

Pass `output_bytes=True` as a keyword argument when requesting bytes from `decrypt()`.

## Key Implementation Details

| Setting | Value |
|---------|-------|
| OAEP hash | SHA-256 |
| Mask generation | MGF1 using SHA-256 |
| OAEP seed length | 32 bytes |
| Randomness | Python's `secrets` module |
| Prime testing | Miller–Rabin, 40 rounds by default |
| Default public exponent | `65537` |
| Default demonstration key size | 2048 bits |
| Minimum supported modulus size | 2048 bits |
| Ciphertext representation | Integer |
| OAEP label | Optional bytes, default `b""` |

## Notes

- **Keep module files together:** `main.py` imports `oaep.py`, `rsa.py`, and `byte_conversion.py`; `rsa.py` imports `primes.py`.
- **Use matching keys:** Encrypt with the public key and decrypt with its corresponding private key.
- **Use the same OAEP label:** A non-empty label supplied during encryption must be supplied unchanged during decryption.
- **Observe message-size limits:** SHA-256 OAEP permits at most 190 bytes with a 2048-bit modulus and 318 bytes with a 3072-bit modulus.
- **Ciphertexts are integers:** A consistent serialization format is needed when storing or transmitting them.
- **Preserve leading zeros:** Convert the decrypted integer to the modulus-sized byte length before OAEP decoding.
- **Encryption is randomized:** A fresh OAEP seed means identical messages normally produce different ciphertexts.
- **Private-key handling:** Private-key components are returned as an integer tuple. Secure persistent key storage is not implemented.
- **Security limitations:** The implementation has not undergone a security audit and does not guarantee constant-time rejection of invalid encodings.
- **Generated files:** Syntax checks and test runs may create `__pycache__/`, `.pytest_cache/`, and `.pyc` files. These are not needed in the submission archive.

## Benchmarking

Run from the project root:

```bash
python benchmark_rsa.py
```

Alternatively:

```bash
make benchmark
```

The benchmark evaluates 2048-bit and 3072-bit RSA using public exponent `65537`.

For each key size, it performs:

- Five key-generation trials.
- 100 RSA integer encryption operations.
- 100 RSA integer decryption operations.

Encryption and decryption use the integer representative `12345` and one generated key pair for each key size. The recovered integer is checked against the original.

The script reports mean and median execution times in seconds.

These measurements cover RSA key generation and integer operations. They do not include OAEP encoding, OAEP decoding, or the complete RSA-OAEP workflow.

## Testing

### Run the complete suite

From the project root:

```bash
python -m pytest -v tests/
```

Alternatively:

```bash
make test
```

### Run one test module

For the public-interface tests:

```bash
python -m pytest -v tests/test_main.py
```

Run this command from the project root, not from inside `tests/`.

### Supplied test cases

87 test cases, including parameterized cases:

| Test module | Cases |
|-------------|------:|
| `tests/test_primes.py` | 7 |
| `tests/test_rsa.py` | 14 |
| `tests/test_oaep.py` | 25 |
| `tests/test_main.py` | 21 |
| `tests/test_integration.py` | 20 |
| **Total** | **87** |

The component-level tests account for 46 cases. The public-interface and integration tests account for the remaining 41 cases.

The `test_integration.py` module runs 10 test functions for both 2048-bit and 3072-bit keys, producing 20 cases.

Running make test gives 87 passed.

Coverage includes:

- Prime generation and Miller–Rabin testing.
- RSA key generation, integer operations, and input validation.
- MGF1 output lengths and determinism.
- OAEP encoding, decoding, and padding validation.
- ASCII, Unicode, empty messages, and raw binary data.
- Fixed-length byte/integer conversion and leading zero bytes.
- Maximum-length messages and rejection of oversized messages.
- Repeated encryption of the same plaintext.
- Incorrect labels, modified ciphertexts, and unrelated private keys.
- Round trips with 2048-bit and 3072-bit keys.

## Reference

RSAES-OAEP is specified in:

Moriarty, K., Kaliski, B., Jonsson, J., Rusch, A.: *PKCS #1: RSA Cryptography Specifications Version 2.2*. RFC 8017 (2016).

- RFC: https://www.rfc-editor.org/rfc/rfc8017
- RSA encryption and decryption primitives: Section 5.1.
- RSAES-OAEP: Section 7.1.
- MGF1: Appendix B.2.1.

The project implements OAEP and MGF1 using SHA-256.

## Disclaimer

This project is intended for educational and academic use. It demonstrates cryptographic concepts and is not a substitute for a vetted cryptographic library in production systems.

Passing functional tests does not establish production readiness, constant-time behaviour, or protection against every possible attack.

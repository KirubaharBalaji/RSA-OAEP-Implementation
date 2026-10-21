"""Integration tests for main.py's RSA-OAEP public interface.

Run from this directory with:
    python -m pytest -v test_main.py
"""
import pytest

import hashlib

from main import (
    DEFAULT_PUBLIC_EXPONENT,
    decrypt,
    decrypt_bytes,
    encrypt,
    encrypt_bytes,
    generate_keys,
)
from byte_conversion import bytes_to_integer, integer_to_bytes, string_to_bytes, bytes_to_string
from oaep import oaep_encode


@pytest.fixture(scope="module")
def keypair_2048():
    return generate_keys(2048)


def test_byte_integer_conversion_preserves_leading_zero_bytes():
    original = b"\x00\x00\x01\x02\x03"
    number = bytes_to_integer(original)
    recovered = integer_to_bytes(number, len(original))
    assert recovered == original
    assert len(recovered) == len(original)


def test_byte_integer_conversion_fixed_length():
    original = b"\x00\x00\x00ABC"
    number = bytes_to_integer(original)
    assert integer_to_bytes(number, 6) == original
    # Fixed-length conversion must pad with leading zero bytes.
    assert integer_to_bytes(bytes_to_integer(b"ABC"), 6) == b"\x00\x00\x00ABC"


def test_byte_integer_conversion_invalid_length_raises():
    with pytest.raises((OverflowError, ValueError)):
        integer_to_bytes(256, 1)


def test_string_byte_conversion_round_trip():
    text = "Encryption"
    assert bytes_to_string(string_to_bytes(text)) == text


@pytest.mark.parametrize("bad_message", [None, 123, b"bytes-not-str"])
def test_encrypt_rejects_non_string_message(bad_message, keypair_2048):
    public_key, _ = keypair_2048
    with pytest.raises(TypeError):
        encrypt(bad_message, public_key)


def test_encrypt_rejects_non_bytes_label(keypair_2048):
    public_key, _ = keypair_2048
    with pytest.raises(TypeError):
        encrypt("hello", public_key, label="not bytes")


def test_decrypt_rejects_non_bytes_label(keypair_2048):
    _, private_key = keypair_2048
    with pytest.raises(TypeError):
        decrypt(1, private_key, label="not bytes")


def test_key_generation_rejects_key_size_below_2048():
    with pytest.raises(ValueError):
        generate_keys(1024)


def test_key_generation_rejects_invalid_key_size_type():
    with pytest.raises(TypeError):
        generate_keys("2048")


def test_encrypt_decrypt_normal_message(keypair_2048):
    public_key, private_key = keypair_2048
    message = "RSA-OAEP integration test"
    assert decrypt(encrypt(message, public_key), private_key) == message


def test_encrypt_decrypt_unicode_message(keypair_2048):
    public_key, private_key = keypair_2048
    message = "Encryption café 🔐 東京"
    assert decrypt(encrypt(message, public_key), private_key) == message


def test_empty_message_round_trip(keypair_2048):
    public_key, private_key = keypair_2048
    assert decrypt(encrypt("", public_key), private_key) == ""



def test_maximum_length_message(keypair_2048):
    public_key, private_key = keypair_2048

    # OAEP maximum: k - 2*hLen - 2.
    # Assumes SHA-256 is used by the OAEP implementation.
    modulus_bytes = (public_key[0].bit_length() + 7) // 8
    max_length = modulus_bytes - 2 * hashlib.sha256().digest_size - 2

    message = "A" * max_length
    ciphertext = encrypt(message, public_key)

    assert decrypt(ciphertext, private_key) == message


def test_oversized_message_rejected(keypair_2048):
    public_key, _ = keypair_2048

    modulus_bytes = (public_key[0].bit_length() + 7) // 8
    max_length = modulus_bytes - 2 * hashlib.sha256().digest_size - 2

    message = "A" * (max_length + 1)

    with pytest.raises((ValueError, OverflowError)):
        encrypt(message, public_key)


def test_same_message_produces_different_ciphertexts(keypair_2048):
    public_key, private_key = keypair_2048
    message = "RSA-OAEP randomness test"

    ciphertext1 = encrypt(message, public_key)
    ciphertext2 = encrypt(message, public_key)

    assert ciphertext1 != ciphertext2
    assert decrypt(ciphertext1, private_key) == message
    assert decrypt(ciphertext2, private_key) == message


def test_modified_ciphertext_rejected(keypair_2048):
    public_key, private_key = keypair_2048
    message = "Detect ciphertext modification"

    ciphertext = encrypt(message, public_key)

    # Assumes ciphertext is represented as an integer.
    modified_ciphertext = ciphertext ^ 1

    with pytest.raises((ValueError, OverflowError)):
        decrypt(modified_ciphertext, private_key)


def test_wrong_private_key_rejected(keypair_2048):
    public_key, _ = keypair_2048
    _, wrong_private_key = generate_keys(2048)

    message = "Wrong private key test"
    ciphertext = encrypt(message, public_key)

    with pytest.raises((ValueError, OverflowError)):
        decrypt(ciphertext, wrong_private_key)


def test_3072_bit_rsa_round_trip():
    public_key, private_key = generate_keys(3072)
    message = "RSA-OAEP 3072-bit integration test"

    ciphertext = encrypt(message, public_key)

    assert decrypt(ciphertext, private_key) == message


def test_binary_data_round_trip(keypair_2048):
    public_key, private_key = keypair_2048

    binary_data = bytes([
        0x00, 0x01, 0x02, 0x7F,
        0x80, 0xFE, 0xFF, 0x00
    ])

    ciphertext = encrypt_bytes(binary_data, public_key)
    recovered_data = decrypt_bytes(ciphertext, private_key)

    assert recovered_data == binary_data
    assert isinstance(recovered_data, bytes)

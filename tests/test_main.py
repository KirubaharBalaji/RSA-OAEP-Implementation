"""Integration tests for main.py's RSA-OAEP public interface.

Run from this directory with:
    python -m pytest -v test_main.py
"""
import pytest

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


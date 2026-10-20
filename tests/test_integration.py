
import pytest

from rsa import generate_keypair, encrypt_int, decrypt_int
from oaep import oaep_encode, oaep_decode


# Generate one key pair for each key size.
# Reuse keys across tests to avoid slow key generation.
@pytest.fixture(scope="module", params=[2048, 3072])
def rsa_keys(request):
    bits = request.param

    print(f"\nGenerating {bits}-bit RSA keys...")
    public_key, private_key = generate_keypair(bits, 65537)

    return public_key, private_key


# Helper: Complete RSA-OAEP encryption
def encrypt_message(message, public_key, label=b""):
    n, e = public_key
    k = (n.bit_length() + 7) // 8

    # OAEP encoding
    encoded = oaep_encode(message, k, label)

    # Convert bytes to integer
    message_int = int.from_bytes(encoded, "big")

    # RSA encryption
    ciphertext_int = encrypt_int(message_int, public_key)

    # Convert ciphertext to fixed-length bytes
    return ciphertext_int.to_bytes(k, "big")


# Helper: Complete RSA-OAEP decryption
def decrypt_message(ciphertext, private_key, label=b""):
    n, d = private_key
    k = (n.bit_length() + 7) // 8

    # Convert ciphertext bytes to integer
    ciphertext_int = int.from_bytes(ciphertext, "big")

    # RSA decryption
    decrypted_int = decrypt_int(ciphertext_int, private_key)

    # Convert integer to fixed-length bytes
    encoded = decrypted_int.to_bytes(k, "big")

    # OAEP decoding
    return oaep_decode(encoded, label)


# Test 1: Normal message
def test_normal_message(rsa_keys):
    public_key, private_key = rsa_keys
    message = b"Hello RSA-OAEP!"

    ciphertext = encrypt_message(message, public_key)
    recovered = decrypt_message(ciphertext, private_key)

    assert recovered == message


# Test 2: Empty message
def test_empty_message(rsa_keys):
    public_key, private_key = rsa_keys
    message = b""

    ciphertext = encrypt_message(message, public_key)
    recovered = decrypt_message(ciphertext, private_key)

    assert recovered == message


# Test 3: Unicode message
def test_unicode_message(rsa_keys):
    public_key, private_key = rsa_keys
    message = "Hello! 你好 🌍".encode("utf-8")

    ciphertext = encrypt_message(message, public_key)
    recovered = decrypt_message(ciphertext, private_key)

    assert recovered.decode("utf-8") == message.decode("utf-8")


# Test 4: Maximum message length
def test_maximum_message_length(rsa_keys):
    public_key, private_key = rsa_keys

    n, e = public_key
    k = (n.bit_length() + 7) // 8

    max_length = k - 2 * 32 - 2
    message = b"A" * max_length

    ciphertext = encrypt_message(message, public_key)
    recovered = decrypt_message(ciphertext, private_key)

    assert recovered == message


# Test 5: Reject oversized message
def test_oversized_message(rsa_keys):
    public_key, private_key = rsa_keys

    n, e = public_key
    k = (n.bit_length() + 7) // 8

    max_length = k - 2 * 32 - 2
    message = b"A" * (max_length + 1)

    with pytest.raises(ValueError):
        encrypt_message(message, public_key)


# Test 6: Randomized encryption
def test_randomized_encryption(rsa_keys):
    public_key, private_key = rsa_keys
    message = b"Same message"

    ciphertext1 = encrypt_message(message, public_key)
    ciphertext2 = encrypt_message(message, public_key)

    assert ciphertext1 != ciphertext2

    assert decrypt_message(ciphertext1, private_key) == message
    assert decrypt_message(ciphertext2, private_key) == message


# Test 7: Wrong OAEP label
def test_wrong_label(rsa_keys):
    public_key, private_key = rsa_keys

    ciphertext = encrypt_message(
        b"Hello",
        public_key,
        label=b"correct"
    )

    with pytest.raises(ValueError):
        decrypt_message(
            ciphertext,
            private_key,
            label=b"wrong"
        )


# Test 8: Corrupted ciphertext
def test_corrupted_ciphertext(rsa_keys):
    public_key, private_key = rsa_keys

    ciphertext = bytearray(
        encrypt_message(b"Hello", public_key)
    )

    # Modify one byte
    ciphertext[-1] ^= 0x01

    with pytest.raises(ValueError):
        decrypt_message(bytes(ciphertext), private_key)


# Test 9: Verify ciphertext length
def test_ciphertext_length(rsa_keys):
    public_key, private_key = rsa_keys

    n, e = public_key
    k = (n.bit_length() + 7) // 8

    ciphertext = encrypt_message(b"Hello", public_key)

    assert len(ciphertext) == k


# Test 10: Byte conversion preserves leading zeros
def test_byte_conversion(rsa_keys):
    public_key, private_key = rsa_keys

    n, e = public_key
    k = (n.bit_length() + 7) // 8

    original = b"\x00\x00\x01\x02\x03"

    integer_value = int.from_bytes(original, "big")

    recovered = integer_value.to_bytes(
        len(original), "big"
    )

    assert recovered == original

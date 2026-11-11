"""Integration layer for the RSA-OAEP implementation.

Combines OAEP encoding (oaep.py), RSA operations (rsa.py) and
byte/integer conversion (byte_conversion.py).
"""

from oaep import oaep_encode, oaep_decode
from rsa import generate_keypair, encrypt_int, decrypt_int
from byte_conversion import bytes_to_integer, integer_to_bytes, string_to_bytes, bytes_to_string


DEFAULT_PUBLIC_EXPONENT = 65537


def generate_keys(bits: int = 2048, e: int = DEFAULT_PUBLIC_EXPONENT):
    """Generate and return (public_key, private_key)."""
    return generate_keypair(bits, e)


def encrypt(message: str, public_key: tuple[int, int], label: bytes = b"") -> int:
    """Encode a string with OAEP and encrypt it with the RSA public key.

    Returns the RSA ciphertext as an integer. The public key is (n, e).
    """
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    if not isinstance(label, bytes):
        raise TypeError("label must be bytes")

    message_bytes = string_to_bytes(message)
    n, _e = public_key
    k = (n.bit_length() + 7) // 8

    encoded_message = oaep_encode(message_bytes, k, label)
    encoded_integer = bytes_to_integer(encoded_message)
    ciphertext = encrypt_int(encoded_integer, public_key)
    return ciphertext


def decrypt(
    ciphertext: int,
    private_key: tuple[int, int],
    label: bytes = b"",
    *,
    output_bytes: bool = False,
) -> str | bytes:
    """Decrypt an RSA-OAEP ciphertext and return the original UTF-8 string.

    Set output_bytes=True to return the raw plaintext bytes instead.
    """
    if not isinstance(label, bytes):
        raise TypeError("label must be bytes")

    n, _d = private_key
    k = (n.bit_length() + 7) // 8

    encoded_integer = decrypt_int(ciphertext, private_key)
    encoded_message = integer_to_bytes(encoded_integer, k)
    message_bytes = oaep_decode(encoded_message, label)

    if output_bytes:
        return message_bytes
    return bytes_to_string(message_bytes)


def encrypt_bytes(message: bytes, public_key: tuple[int, int], label: bytes = b"") -> int:
    """Encrypt bytes directly, without converting through a string."""
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(label, bytes):
        raise TypeError("label must be bytes")

    n, _e = public_key
    k = (n.bit_length() + 7) // 8
    encoded_message = oaep_encode(message, k, label)
    return encrypt_int(bytes_to_integer(encoded_message), public_key)


def decrypt_bytes(ciphertext: int, private_key: tuple[int, int], label: bytes = b"") -> bytes:
    """Decrypt to the original bytes."""
    return decrypt(ciphertext, private_key, label, output_bytes=True)


if __name__ == "__main__":
    public_key, private_key = generate_keys(2048)
    plaintext = input("Message to encrypt: ")
    encrypted = encrypt(plaintext, public_key)
    recovered = decrypt(encrypted, private_key)

    print("Original :", plaintext)
    print("Ciphertext (integer):", encrypted)
    print("Recovered:", recovered)
    print("Round trip successful:", recovered == plaintext)

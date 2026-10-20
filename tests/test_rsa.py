
import pytest

from rsa import generate_keypair, encrypt_int, decrypt_int


def test_key_generation():
    public_key, private_key = generate_keypair(2048, 65537)

    n, e = public_key
    private_n, d = private_key

    assert n == private_n
    assert n.bit_length() == 2048
    assert e == 65537
    assert d > 0


def test_encrypt_decrypt():
    public_key, private_key = generate_keypair(2048, 65537)

    message = 12345
    ciphertext = encrypt_int(message, public_key)
    decrypted = decrypt_int(ciphertext, private_key)

    assert decrypted == message


def test_encrypt_zero():
    public_key, private_key = generate_keypair(2048, 65537)

    ciphertext = encrypt_int(0, public_key)
    assert decrypt_int(ciphertext, private_key) == 0


def test_encrypt_negative_number():
    public_key, _ = generate_keypair(2048, 65537)

    with pytest.raises(ValueError):
        encrypt_int(-1, public_key)


def test_encrypt_number_too_large():
    public_key, _ = generate_keypair(2048, 65537)
    n, _ = public_key

    with pytest.raises(ValueError):
        encrypt_int(n, public_key)


def test_decrypt_negative_number():
    _, private_key = generate_keypair(2048, 65537)

    with pytest.raises(ValueError):
        decrypt_int(-1, private_key)

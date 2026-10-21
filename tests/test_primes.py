
import pytest

from primes import is_probable_prime, generate_prime


def test_small_primes():
    assert is_probable_prime(2)
    assert is_probable_prime(3)
    assert is_probable_prime(17)
    assert is_probable_prime(97)


def test_composite_numbers():
    assert not is_probable_prime(0)
    assert not is_probable_prime(1)
    assert not is_probable_prime(4)
    assert not is_probable_prime(15)
    assert not is_probable_prime(100)


def test_generate_prime_has_correct_bit_length():
    for bits in [8, 16, 32]:
        prime = generate_prime(bits)
        assert prime.bit_length() == bits
        assert is_probable_prime(prime)


def test_invalid_prime_size():
    with pytest.raises(ValueError):
        generate_prime(1)


def test_invalid_rounds():
    with pytest.raises(ValueError):
        is_probable_prime(17, rounds=0)

def test_invalid_primality_input_types():
    with pytest.raises(TypeError):
        is_probable_prime("17")

    with pytest.raises(TypeError):
        is_probable_prime(17.5)

    with pytest.raises(TypeError):
        is_probable_prime(True)


def test_invalid_rounds_types():
    with pytest.raises(TypeError):
        is_probable_prime(17, rounds="10")

    with pytest.raises(TypeError):
        is_probable_prime(17, rounds=2.5)

    with pytest.raises(TypeError):
        is_probable_prime(17, rounds=True)

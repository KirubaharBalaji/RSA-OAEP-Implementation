
import hashlib
import pytest

from oaep import mgf1, oaep_encode, oaep_decode


# ==========================================
# MGF1 TESTS
# ==========================================

# Test 1: Generate a 32-byte mask
def test_mgf1_32_bytes():
    mask = mgf1(b"hello", 32)

    assert isinstance(mask, bytes)
    assert len(mask) == 32


# Test 2: Generate a 70-byte mask
def test_mgf1_70_bytes():
    mask = mgf1(b"hello", 70)

    assert isinstance(mask, bytes)
    assert len(mask) == 70


# Test 3: Check deterministic output
def test_mgf1_deterministic():
    assert mgf1(b"hello", 32) == mgf1(b"hello", 32)


# Test 4: Check requested length
def test_mgf1_correct_length():
    for length in [0, 1, 32, 64, 70, 100]:
        assert len(mgf1(b"hello", length)) == length


# ==========================================
# OAEP ENCODING AND DECODING TESTS
# ==========================================

# Test 5: OAEP encoding structure
def test_oaep_encoding():
    message = b"Hello"
    k = 256

    encoded = oaep_encode(message, k)

    assert len(encoded) == 256
    assert encoded[0] == 0


# Test 6: OAEP encoding/decoding round-trip
def test_oaep_decoding():
    message = b"Hello"

    encoded = oaep_encode(message, 256)
    decoded = oaep_decode(encoded)

    assert decoded == message


# Test 7: Empty message
def test_empty_message():
    encoded = oaep_encode(b"", 256)

    assert oaep_decode(encoded) == b""


# Test 8: Maximum message length for 2048-bit RSA
def test_maximum_message_length_2048():
    message = b"A" * 190

    encoded = oaep_encode(message, 256)

    assert oaep_decode(encoded) == message


# Test 9: Oversized message should be rejected
def test_oversized_message_2048():
    with pytest.raises(ValueError):
        oaep_encode(b"A" * 191, 256)


# Test 10: Wrong label should be rejected
def test_wrong_label():
    encoded = oaep_encode(
        b"Hello",
        256,
        label=b"correct"
    )

    with pytest.raises(ValueError):
        oaep_decode(encoded, label=b"wrong")


# Test 11: Corrupted padding should be rejected
def test_corrupted_padding():
    encoded = bytearray(oaep_encode(b"Hello", 256))
    encoded[0] = 1

    with pytest.raises(ValueError):
        oaep_decode(bytes(encoded))


# ==========================================
# INDEPENDENT VERIFICATION
# ==========================================

# Test 12: Independently verify MGF1
def test_mgf1_independent_verification():
    seed = b"hello"

    expected = hashlib.sha256(
        seed + b"\x00\x00\x00\x00"
    ).digest()

    actual = mgf1(seed, 32)

    assert actual == expected


# Helper: Independent MGF1 implementation
def reference_mgf1(seed, length):
    result = b""
    counter = 0

    while len(result) < length:
        counter_bytes = counter.to_bytes(4, "big")
        result += hashlib.sha256(seed + counter_bytes).digest()
        counter += 1

    return result[:length]


# Test 13: Independently verify OAEP encoding
def test_oaep_encoding_structure():
    message = b"Hello"
    k = 256
    h_len = 32

    encoded = oaep_encode(message, k)

    masked_seed = encoded[1:33]
    masked_db = encoded[33:]

    # Recover the seed
    seed_mask = reference_mgf1(masked_db, h_len)
    seed = bytes(
        a ^ b for a, b in zip(masked_seed, seed_mask)
    )

    # Recover the data block
    db_mask = reference_mgf1(seed, k - h_len - 1)
    db = bytes(
        a ^ b for a, b in zip(masked_db, db_mask)
    )

    # Construct expected data block independently
    l_hash = hashlib.sha256(b"").digest()
    ps = b"\x00" * (
        k - len(message) - 2 * h_len - 2
    )

    expected_db = l_hash + ps + b"\x01" + message

    assert db == expected_db


# ==========================================
# ADDITIONAL INPUT VALIDATION TESTS
# ==========================================

# Test 14: Reject negative mask length
def test_mgf1_negative_length():
    with pytest.raises(ValueError):
        mgf1(b"hello", -1)


# Test 15: Reject non-integer mask length
def test_mgf1_invalid_length_type():
    with pytest.raises(TypeError):
        mgf1(b"hello", "32")


# Test 16: Reject non-bytes seed
def test_mgf1_invalid_seed_type():
    with pytest.raises(TypeError):
        mgf1("hello", 32)


# Test 17: Reject non-bytes message
def test_oaep_invalid_message_type():
    with pytest.raises(TypeError):
        oaep_encode("Hello", 256)


# Test 18: Reject invalid modulus length
def test_oaep_invalid_modulus_length():
    with pytest.raises(ValueError):
        oaep_encode(b"Hello", 64)


# Test 19: Reject invalid label type
def test_oaep_invalid_label_type():
    with pytest.raises(TypeError):
        oaep_encode(b"Hello", 256, label="label")


# ==========================================
# 3072-BIT OAEP TESTS
# ==========================================

# Test 20: 3072-bit OAEP round-trip
def test_oaep_3072_roundtrip():
    message = b"Hello RSA-OAEP 3072"

    encoded = oaep_encode(message, 384)

    assert len(encoded) == 384
    assert oaep_decode(encoded) == message


# Test 21: Maximum message length for 3072-bit RSA
def test_maximum_message_length_3072():
    message = b"A" * 318

    encoded = oaep_encode(message, 384)

    assert oaep_decode(encoded) == message


# Test 22: Reject oversized message for 3072-bit RSA
def test_oversized_message_3072():
    with pytest.raises(ValueError):
        oaep_encode(b"A" * 319, 384)


# ==========================================
# RANDOMIZATION AND PADDING TESTS
# ==========================================

# Test 23: Same message should produce different encodings
def test_oaep_randomization():
    message = b"Same message"

    encoded1 = oaep_encode(message, 256)
    encoded2 = oaep_encode(message, 256)

    assert encoded1 != encoded2

    assert oaep_decode(encoded1) == message
    assert oaep_decode(encoded2) == message


# Test 24: Reject corrupted masked data
def test_corrupted_masked_data():
    encoded = bytearray(oaep_encode(b"Hello", 256))

    encoded[50] ^= 0x01

    with pytest.raises(ValueError):
        oaep_decode(bytes(encoded))


# Test 25: Reject invalid encoded input type
def test_oaep_decode_invalid_type():
    with pytest.raises(TypeError):
        oaep_decode("invalid")

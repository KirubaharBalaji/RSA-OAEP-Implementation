
from oaep import mgf1

# Test 1: Generate a 32-byte mask
mask1 = mgf1(b"hello", 32)

print("Test 1: 32-byte mask")
print("Length:", len(mask1))
print("Mask:", mask1.hex())

# Test 2: Generate a 70-byte mask
mask2 = mgf1(b"hello", 70)

print("\nTest 2: 70-byte mask")
print("Length:", len(mask2))
print("Mask:", mask2.hex())

# Test 3: Check the output is deterministic
assert mgf1(b"hello", 32) == mgf1(b"hello", 32)
print("\nTest 3: Deterministic output - PASS")

# Test 4: Check requested length
assert len(mask2) == 70
print("Test 4: Correct length - PASS")

from oaep import oaep_encode

message = b"Hello"
k = 256  # 2048-bit RSA modulus = 256 bytes

encoded = oaep_encode(message, k)

print("\nTest 5: OAEP encoding")
print("Encoded length:", len(encoded))
print("First byte:", encoded[0])
print("Encoded message:", encoded.hex())

assert len(encoded) == 256
assert encoded[0] == 0
print("Test 5: OAEP encoding - PASS")


from oaep import oaep_decode

print("\nTest 6: OAEP decoding")

original_message = b"Hello"

encoded = oaep_encode(original_message, 256)
decoded = oaep_decode(encoded)

print("Original message:", original_message)
print("Decoded message:", decoded)

assert decoded == original_message

print("Test 6: OAEP decoding - PASS")



# Test 7: Empty message
encoded = oaep_encode(b"", 256)
assert oaep_decode(encoded) == b""
print("Test 7: Empty message - PASS")

# Test 8: Maximum message length for 2048-bit RSA + SHA-256
message = b"A" * 190
encoded = oaep_encode(message, 256)
assert oaep_decode(encoded) == message
print("Test 8: Maximum message length - PASS")


# Test 9: Oversized message should be rejected
try:
    oaep_encode(b"A" * 191, 256)
except ValueError:
    print("Test 9: Oversized message rejected - PASS")
else:
    raise AssertionError("Test 9 FAILED: Oversized message accepted")


# Test 10: Wrong label should be rejected
encoded = oaep_encode(b"Hello", 256, label=b"correct")

try:
    oaep_decode(encoded, label=b"wrong")
except ValueError:
    print("Test 10: Wrong label rejected - PASS")
else:
    raise AssertionError("Test 10 FAILED: Wrong label accepted")


# Test 11: Corrupted padding should be rejected
encoded = bytearray(oaep_encode(b"Hello", 256))
encoded[0] = 1

try:
    oaep_decode(bytes(encoded))
except ValueError:
    print("Test 11: Corrupted padding rejected - PASS")
else:
    raise AssertionError("Test 11 FAILED: Corrupted padding accepted")



# Test 12: Independent MGF1 verification
import hashlib

seed = b"hello"

expected = hashlib.sha256(
    seed + b"\x00\x00\x00\x00"
).digest()

actual = mgf1(seed, 32)

assert actual == expected

print("Test 12: Independent MGF1 verification - PASS")


# Test 13: Independently verify OAEP encoding
import hashlib

message = b"Hello"
k = 256
h_len = 32

encoded = oaep_encode(message, k)

# Extract the masked components
masked_seed = encoded[1:33]
masked_db = encoded[33:]

# Independently implement MGF1 for this test
def reference_mgf1(seed, length):
    result = b""
    counter = 0

    while len(result) < length:
        counter_bytes = counter.to_bytes(4, "big")
        result += hashlib.sha256(seed + counter_bytes).digest()
        counter += 1

    return result[:length]

# Recover seed and data block
seed_mask = reference_mgf1(masked_db, h_len)
seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

db_mask = reference_mgf1(seed, k - h_len - 1)
db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

# Independently construct the expected data block
l_hash = hashlib.sha256(b"").digest()
ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
expected_db = l_hash + ps + b"\x01" + message

assert db == expected_db
print("Test 13: OAEP encoding structure - PASS")

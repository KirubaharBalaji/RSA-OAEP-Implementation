
import hashlib
import secrets


def mgf1(seed: bytes, length: int) -> bytes:
    """Generate a mask using MGF1 with SHA-256."""

    # Validate inputs
    if not isinstance(seed, bytes):
        raise TypeError("Seed must be bytes")

    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("Mask length must be an integer")

    # SHA-256 produces 32 bytes per hash
    h_len = hashlib.sha256().digest_size

    if length < 0 or length > h_len * (2**32):
        raise ValueError("Invalid mask length")

    mask = bytearray()

    # Generate enough hash outputs to reach the required length
    for counter in range((length + h_len - 1) // h_len):

        # Convert counter to 4 bytes (big-endian)
        counter_bytes = counter.to_bytes(4, "big")

        # Hash seed + counter
        digest = hashlib.sha256(seed + counter_bytes).digest()

        # Add the hash output to our mask
        mask.extend(digest)

    # Return exactly the requested number of bytes
    return bytes(mask[:length])


def oaep_encode(message: bytes, k: int, label: bytes = b"") -> bytes:
    """Encode a message using OAEP with SHA-256."""

    # Validate inputs
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")

    if not isinstance(k, int) or isinstance(k, bool):
        raise TypeError("Modulus length must be an integer")

    if not isinstance(label, bytes):
        raise TypeError("Label must be bytes")

    h_len = hashlib.sha256().digest_size

    # Check whether the RSA modulus is large enough
    if k < 2 * h_len + 2:
        raise ValueError("RSA modulus is too short for OAEP")

    # Check whether the message fits
    if len(message) > k - 2 * h_len - 2:
        raise ValueError("Message is too long")

    # Step 1: Hash the optional label
    l_hash = hashlib.sha256(label).digest()

    # Step 2: Construct the data block
    ps_length = k - len(message) - 2 * h_len - 2
    ps = b"\x00" * ps_length

    db = l_hash + ps + b"\x01" + message

    # Step 3: Generate a random seed
    seed = secrets.token_bytes(h_len)

    # Step 4: Mask the data block
    db_mask = mgf1(seed, k - h_len - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    # Step 5: Mask the seed
    seed_mask = mgf1(masked_db, h_len)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    # Step 6: Construct the encoded message
    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded: bytes, label: bytes = b"") -> bytes:
    """Decode an OAEP-encoded message using SHA-256."""

    # Validate inputs
    if not isinstance(encoded, bytes):
        raise TypeError("Encoded message must be bytes")

    if not isinstance(label, bytes):
        raise TypeError("Label must be bytes")

    h_len = hashlib.sha256().digest_size
    k = len(encoded)

    # Check minimum encoded length
    if k < 2 * h_len + 2:
        raise ValueError("Encoded message is too short")

    # The first byte must be 0x00
    if encoded[0] != 0:
        raise ValueError("Invalid OAEP padding")

    # Separate the encoded message into its components
    masked_seed = encoded[1:1 + h_len]
    masked_db = encoded[1 + h_len:]

    # Recover the original seed
    seed_mask = mgf1(masked_db, h_len)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    # Recover the original data block
    db_mask = mgf1(seed, k - h_len - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    # Verify the label hash
    expected_l_hash = hashlib.sha256(label).digest()
    recovered_l_hash = db[:h_len]

    if not secrets.compare_digest(recovered_l_hash, expected_l_hash):
        raise ValueError("Invalid OAEP padding")

    # Remove the zero padding and find the 0x01 separator
    remaining = db[h_len:]

    try:
        separator_index = remaining.index(b"\x01")
    except ValueError:
        raise ValueError("Invalid OAEP padding") from None

    # All bytes before the separator must be 0x00
    if any(byte != 0 for byte in remaining[:separator_index]):
        raise ValueError("Invalid OAEP padding")

    # Return the original plaintext
    return remaining[separator_index + 1:]

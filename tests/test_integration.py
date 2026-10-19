
from rsa import generate_keypair, encrypt_int, decrypt_int
from oaep import oaep_encode, oaep_decode

# Step 1: Generate RSA keys
print("Generating RSA keys...")
public_key, private_key = generate_keypair(2048)

# Step 2: Calculate modulus length in bytes
n, e = public_key
k = (n.bit_length() + 7) // 8

# Step 3: Original message
message = b"Hello RSA-OAEP!"
print("Original message:", message)

# Step 4: Apply OAEP encoding
encoded = oaep_encode(message, k)
print("OAEP encoding completed")

# Step 5: Convert bytes to integer for RSA
message_int = int.from_bytes(encoded, "big")

# Step 6: RSA encryption
ciphertext_int = encrypt_int(message_int, public_key)
print("RSA encryption completed")

# Step 7: RSA decryption
decrypted_int = decrypt_int(ciphertext_int, private_key)
print("RSA decryption completed")

# Step 8: Convert integer back to bytes
decrypted_encoded = decrypted_int.to_bytes(k, "big")

# Step 9: Remove OAEP padding
recovered_message = oaep_decode(decrypted_encoded)
print("Recovered message:", recovered_message)

# Step 10: Verify
assert recovered_message == message
print("RSA-OAEP INTEGRATION TEST - PASS")

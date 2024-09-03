import hashlib
from ecdsa import VerifyingKey, SECP256k1

# Step 1: Define the public key (hardcoded example)
public_key_hex = "04ffa86eb932c8e50aeda2d191cfade48dd6c2d04b9f92882e68b6ba72606a07c41413d526b358f6586619a34d686b3d12b9e0c6ac9873424a9722405b67bc76c7"

# Convert the hex string to bytes
public_key_bytes = bytes.fromhex(public_key_hex)

# Step 2: Compress the public key
def compress_public_key(public_key_bytes):
    if public_key_bytes[0] != 0x04:
        raise ValueError("Invalid public key format")
    x = public_key_bytes[1:33]
    y = public_key_bytes[33:65]
    if int.from_bytes(y, byteorder='big') % 2 == 0:
        compressed_key = b'\x02' + x
    else:
        compressed_key = b'\x03' + x
    return compressed_key


compressed_public_key = compress_public_key(public_key_bytes)
print(f"Compressed Public Key: {compressed_public_key.hex()}")

# Step 3: Compute SHA-256 over the compressed public key
sha256_hash = hashlib.sha256(compressed_public_key).digest()
print(f"SHA-256 Hash: {sha256_hash.hex()}")

# Step 4: Compute RIPEMD-160 over the SHA-256 hash
ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
print(f"RIPEMD-160 Hash: {ripemd160_hash.hex()}")

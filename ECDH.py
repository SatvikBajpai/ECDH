import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

# --- 1. Public Setup ---
# Alice and Bob agree on a curve. We'll use SECP384R1 (a 384-bit curve).
# This is their shared 'G' (generator point) and curve parameters.
print("Using curve: SECP384R1 (also known as P-384)\n")
curve = ec.SECP384R1()

# --- 2. Alice's Side ---
# Alice picks a secret integer 'a' (her private key)
alice_private_key = ec.generate_private_key(curve)
print("--- Alice's Side ---")
print("Alice generates her private key (kept secret).")

# 3. Alice computes her public key: P_A = a * G
alice_public_key = alice_private_key.public_key()

# Alice serializes her public key to send to Bob.
alice_public_bytes = alice_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"Alice's Public Key (sent to Bob):\n{alice_public_bytes.decode('utf-8')}")


# --- 4. Bob's Side ---
# Bob picks a secret integer 'b' (his private key)
bob_private_key = ec.generate_private_key(curve)
print("--- Bob's Side ---")
print("Bob generates his private key (kept secret).")

# 5. Bob computes his public key: P_B = b * G
bob_public_key = bob_private_key.public_key()

# Bob serializes his public key to send to Alice.
bob_public_bytes = bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"Bob's Public Key (sent to Alice):\n{bob_public_bytes.decode('utf-8')}")


# --- 6. Alice Computes the Shared Secret ---
# Alice receives bob_public_key (P_B)
# She computes S = a * P_B = (ab) * G
alice_shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)

# --- 7. Bob Computes the Shared Secret ---
# Bob receives alice_public_key (P_A)
# He computes S = b * P_A = (ba) * G
bob_shared_secret = bob_private_key.exchange(ec.ECDH(), alice_public_key)

# --- 8. Verification ---
print("--- Shared Secret Verification ---")
if alice_shared_secret == bob_shared_secret:
    print("✅ SUCCESS: Alice and Bob derived the same raw shared secret.")
    print(f"Raw Secret (first 16 bytes): {alice_shared_secret[:16].hex()}...")
else:
    print("❌ FAILURE: Shared secrets do not match!")


# --- 9. Final Step: Key Derivation (HKDF) ---
# The raw secret is not a good key. We derive a 32-byte (256-bit) key
# from it using a Key Derivation Function (KDF).
print("\n--- Key Derivation (using HKDF) ---")

# Alice derives the final key
derived_key_alice = HKDF(
    algorithm=hashes.SHA256(),
    length=32,  # We want a 256-bit key (32 bytes)
    salt=None,  # Salt is recommended but omitted for simplicity
    info=b'ecdhe-example-protocol', # Application-specific info
).derive(alice_shared_secret)

# Bob derives the final key
derived_key_bob = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'ecdhe-example-protocol',
).derive(bob_shared_secret)

if derived_key_alice == derived_key_bob:
    print("✅ SUCCESS: Both parties derived the same final 256-bit encryption key.")
    print(f"Final Key: {derived_key_alice.hex()}")
    print("This key can now be used for AES-256 symmetric encryption.")
else:
    print("❌ FAILURE: Derived keys do not match!")
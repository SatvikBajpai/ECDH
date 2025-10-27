#!/bin/bash

# ECDH Key Exchange using OpenSSL
# This script demonstrates ECDH key exchange using the same curve as ECDH.py

echo "Using curve: SECP384R1 (also known as P-384)"
echo ""

# Clean up any existing shared secret files from previous runs
rm -f alice_shared.bin bob_shared.bin 2>/dev/null

# --- 1. Alice's Side ---
echo "--- Alice's Side ---"

# Check if Alice's keys already exist (from Python run)
if [ -f "alice_private.pem" ] && [ -f "alice_public.pem" ]; then
    echo "Alice loading her private key from alice_private.pem"
else
    echo "Alice generates her private key (kept secret)."
    # Generate Alice's private key using secp384r1 curve
    openssl ecparam -name secp384r1 -genkey -noout -out alice_private.pem
    # Extract Alice's public key
    openssl ec -in alice_private.pem -pubout -out alice_public.pem 2>/dev/null
fi

echo "Alice's Public Key (sent to Bob):"
cat alice_public.pem
echo ""

# --- 2. Bob's Side ---
echo "--- Bob's Side ---"

# Check if Bob's keys already exist (from Python run)
if [ -f "bob_private.pem" ] && [ -f "bob_public.pem" ]; then
    echo "Bob loading his private key from bob_private.pem"
else
    echo "Bob generates his private key (kept secret)."
    # Generate Bob's private key using secp384r1 curve
    openssl ecparam -name secp384r1 -genkey -noout -out bob_private.pem
    # Extract Bob's public key
    openssl ec -in bob_private.pem -pubout -out bob_public.pem 2>/dev/null
fi

echo "Bob's Public Key (sent to Alice):"
cat bob_public.pem
echo ""

# --- 3. Alice Computes the Shared Secret ---
# Alice uses her private key and Bob's public key
openssl pkeyutl -derive -inkey alice_private.pem -peerkey bob_public.pem -out alice_shared.bin 2>/dev/null

# --- 4. Bob Computes the Shared Secret ---
# Bob uses his private key and Alice's public key
openssl pkeyutl -derive -inkey bob_private.pem -peerkey alice_public.pem -out bob_shared.bin 2>/dev/null

# --- 5. Verification ---
echo "--- Shared Secret Verification ---"

# Get hex representation of both shared secrets
alice_hex=$(xxd -p alice_shared.bin | tr -d '\n')
bob_hex=$(xxd -p bob_shared.bin | tr -d '\n')

if [ "$alice_hex" = "$bob_hex" ]; then
    echo "SUCCESS: Alice and Bob derived the same raw shared secret."
    # Display first 16 bytes (32 hex characters)
    echo "Raw Secret (first 16 bytes): ${alice_hex:0:32}..."
else
    echo "FAILURE: Shared secrets do not match!"
    echo "Alice's secret: $alice_hex"
    echo "Bob's secret: $bob_hex"
fi
echo ""

# --- 6. Final Step: Key Derivation (HKDF) ---
echo "--- Key Derivation (using HKDF) ---"

# Derive a 32-byte key using HKDF with SHA256
# info parameter: "ecdhe-example-protocol"
info_hex=$(echo -n "ecdhe-example-protocol" | xxd -p | tr -d '\n')

# Alice derives the final key
alice_key=$(openssl kdf -binary -keylen 32 -kdfopt digest:SHA256 -kdfopt hexkey:"$alice_hex" -kdfopt hexinfo:"$info_hex" HKDF 2>/dev/null | xxd -p | tr -d '\n')

# Bob derives the final key
bob_key=$(openssl kdf -binary -keylen 32 -kdfopt digest:SHA256 -kdfopt hexkey:"$bob_hex" -kdfopt hexinfo:"$info_hex" HKDF 2>/dev/null | xxd -p | tr -d '\n')

if [ "$alice_key" = "$bob_key" ]; then
    echo "SUCCESS: Both parties derived the same final 256-bit encryption key."
    echo "Final Key: $alice_key"
    echo "This key can now be used for AES-256 symmetric encryption."
else
    echo "FAILURE: Derived keys do not match!"
    echo "Alice's key: $alice_key"
    echo "Bob's key: $bob_key"
fi
echo ""

# Save the keys and secrets for comparison
echo "$alice_hex" > alice_shared.hex
echo "$bob_hex" > bob_shared.hex
echo "$alice_key" > alice_derived.hex
echo "$bob_key" > bob_derived.hex

echo "Keys saved to files for comparison:"
echo "  - alice_shared.hex, bob_shared.hex: raw shared secrets"
echo "  - alice_derived.hex, bob_derived.hex: derived keys"

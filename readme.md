# 12. Demonstrate, using Python code and the OpenSSL library, the Diﬃe-Hellman key exchange over elliptic curve group.
### Chaitanya Modi, Jiya Agrawal, Satvik Bajpai

Following is the implementation and comparison of ECDH key exchange using Python and OpenSSL.

## Files

### Core Implementations

- *ECDH.py* - Basic ECDH demonstration with random keys (Python/cryptography library)
- *ECDH_with_fixed_keys.py* - ECDH with key persistence to file for comparison
- *ECDH_openssl.sh* - ECDH implementation using OpenSSL commands

### Comparison Tools

- *compare_ecdh.py* - Runs both Python and OpenSSL implementations with same keys, verifies they produce identical results

## How to Run

### Basic demonstration:
bash
python ECDH.py


### Compare Python vs OpenSSL:
bash
python compare_ecdh.py

This will:
1. Generate keys using Python implementation
2. Compute shared secrets and derive encryption keys
3. Use the same keys with OpenSSL
4. Verify both implementations produce identical results

### Run just OpenSSL version:
bash
bash ECDH_openssl.sh

## Implementation Details

Both implementations:
- Use SECP384R1 (P-384) elliptic curve
- Perform ECDH key exchange
- Derive final 256-bit key using HKDF-SHA256
- Save intermediate values for verification

The comparison script validates that Python (cryptography library) and OpenSSL produce byte-identical shared secrets and derived keys, proving correctness across implementations.

We acknowledge that we utilised Claude for assistance in completing this assignment.

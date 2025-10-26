import unittest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization


class TestECDH(unittest.TestCase):
    """Test cases for Elliptic Curve Diffie-Hellman key exchange"""

    def setUp(self):
        """Set up test fixtures before each test method"""
        self.curve = ec.SECP384R1()

    def test_shared_secret_equality(self):
        """Test that Alice and Bob derive the same shared secret"""
        # Generate keys for Alice
        alice_private_key = ec.generate_private_key(self.curve)
        alice_public_key = alice_private_key.public_key()

        # Generate keys for Bob
        bob_private_key = ec.generate_private_key(self.curve)
        bob_public_key = bob_private_key.public_key()

        # Exchange and compute shared secrets
        alice_shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)
        bob_shared_secret = bob_private_key.exchange(ec.ECDH(), alice_public_key)

        # Verify they match
        self.assertEqual(alice_shared_secret, bob_shared_secret)

    def test_derived_key_equality(self):
        """Test that both parties derive the same final encryption key"""
        # Generate keys
        alice_private_key = ec.generate_private_key(self.curve)
        alice_public_key = alice_private_key.public_key()
        bob_private_key = ec.generate_private_key(self.curve)
        bob_public_key = bob_private_key.public_key()

        # Compute shared secrets
        alice_shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)
        bob_shared_secret = bob_private_key.exchange(ec.ECDH(), alice_public_key)

        # Derive keys using HKDF
        derived_key_alice = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'test-protocol',
        ).derive(alice_shared_secret)

        derived_key_bob = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'test-protocol',
        ).derive(bob_shared_secret)

        # Verify derived keys match
        self.assertEqual(derived_key_alice, derived_key_bob)

    def test_different_private_keys_produce_different_secrets(self):
        """Test that different private keys produce different shared secrets"""
        # Alice and Bob
        alice_private_key = ec.generate_private_key(self.curve)
        alice_public_key = alice_private_key.public_key()
        bob_private_key = ec.generate_private_key(self.curve)
        bob_public_key = bob_private_key.public_key()

        # Eve (eavesdropper) with her own keys
        eve_private_key = ec.generate_private_key(self.curve)
        eve_public_key = eve_private_key.public_key()

        # Alice-Bob shared secret
        alice_bob_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)

        # Alice-Eve shared secret (different exchange)
        alice_eve_secret = alice_private_key.exchange(ec.ECDH(), eve_public_key)

        # These should be different
        self.assertNotEqual(alice_bob_secret, alice_eve_secret)

    def test_key_serialization_deserialization(self):
        """Test that public keys can be serialized and deserialized"""
        # Generate a key pair
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()

        # Serialize the public key
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Deserialize it
        loaded_public_key = serialization.load_pem_public_key(public_bytes)

        # Verify we can use the loaded key in ECDH
        bob_private_key = ec.generate_private_key(self.curve)
        bob_public_key = bob_private_key.public_key()

        # Exchange with original key
        secret1 = private_key.exchange(ec.ECDH(), bob_public_key)

        # Exchange with deserialized key (Bob's perspective)
        secret2 = bob_private_key.exchange(ec.ECDH(), loaded_public_key)

        # Verify the exchange worked
        self.assertEqual(
            secret1,
            bob_private_key.exchange(ec.ECDH(), public_key)
        )

    def test_different_info_produces_different_keys(self):
        """Test that different HKDF info parameters produce different keys"""
        # Generate keys and shared secret
        alice_private_key = ec.generate_private_key(self.curve)
        alice_public_key = alice_private_key.public_key()
        bob_private_key = ec.generate_private_key(self.curve)
        bob_public_key = bob_private_key.public_key()

        shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)

        # Derive keys with different info parameters
        key1 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'protocol-v1',
        ).derive(shared_secret)

        key2 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'protocol-v2',
        ).derive(shared_secret)

        # Different info should produce different keys
        self.assertNotEqual(key1, key2)

    def test_multiple_curves(self):
        """Test ECDH with different elliptic curves"""
        curves = [
            ec.SECP256R1(),  # P-256
            ec.SECP384R1(),  # P-384
            ec.SECP521R1(),  # P-521
        ]

        for curve in curves:
            with self.subTest(curve=curve.name):
                # Generate keys
                alice_private_key = ec.generate_private_key(curve)
                alice_public_key = alice_private_key.public_key()
                bob_private_key = ec.generate_private_key(curve)
                bob_public_key = bob_private_key.public_key()

                # Compute shared secrets
                alice_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)
                bob_secret = bob_private_key.exchange(ec.ECDH(), alice_public_key)

                # Verify they match
                self.assertEqual(alice_secret, bob_secret)

    def test_shared_secret_length(self):
        """Test that shared secret has expected length for the curve"""
        # For SECP384R1 (P-384), the shared secret should be 48 bytes
        alice_private_key = ec.generate_private_key(self.curve)
        alice_public_key = alice_private_key.public_key()
        bob_private_key = ec.generate_private_key(self.curve)
        bob_public_key = bob_private_key.public_key()

        shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)

        # SECP384R1 produces 48-byte (384-bit) shared secrets
        self.assertEqual(len(shared_secret), 48)

    def test_derived_key_length(self):
        """Test that derived key has the requested length"""
        alice_private_key = ec.generate_private_key(self.curve)
        alice_public_key = alice_private_key.public_key()
        bob_private_key = ec.generate_private_key(self.curve)
        bob_public_key = bob_private_key.public_key()

        shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)

        # Test different key lengths
        for key_length in [16, 32, 64]:
            with self.subTest(key_length=key_length):
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=key_length,
                    salt=None,
                    info=b'test',
                ).derive(shared_secret)

                self.assertEqual(len(derived_key), key_length)

    def test_deterministic_key_derivation(self):
        """Test that key derivation is deterministic for the same input"""
        alice_private_key = ec.generate_private_key(self.curve)
        bob_private_key = ec.generate_private_key(self.curve)
        bob_public_key = bob_private_key.public_key()

        shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)

        # Derive the same key twice
        key1 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'test-protocol',
        ).derive(shared_secret)

        key2 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'test-protocol',
        ).derive(shared_secret)

        # Should be identical
        self.assertEqual(key1, key2)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)

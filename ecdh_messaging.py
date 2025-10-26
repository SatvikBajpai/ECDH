"""
ECDH Secure Messaging Example
This demonstrates a complete messaging system using ECDH for key exchange
and AES-GCM for message encryption.
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization


class SecureMessenger:
    """A secure messenger using ECDH key exchange and AES-GCM encryption"""

    def __init__(self, name, curve=None):
        """
        Initialize a secure messenger

        Args:
            name: Identifier for this messenger (e.g., "Alice", "Bob")
            curve: Elliptic curve to use (defaults to SECP384R1)
        """
        self.name = name
        self.curve = curve or ec.SECP384R1()

        # Generate this party's key pair
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key = self.private_key.public_key()

        # Storage for peer's public key and derived encryption key
        self.peer_public_key = None
        self.shared_encryption_key = None

        print(f"[{self.name}] Generated key pair using {self.curve.name}")

    def get_public_key_bytes(self):
        """Export public key for transmission to peer"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def receive_peer_public_key(self, peer_public_key_bytes):
        """
        Receive and process peer's public key, then derive shared encryption key

        Args:
            peer_public_key_bytes: PEM-encoded public key from peer
        """
        # Deserialize peer's public key
        self.peer_public_key = serialization.load_pem_public_key(
            peer_public_key_bytes
        )

        # Perform ECDH key exchange
        shared_secret = self.private_key.exchange(ec.ECDH(), self.peer_public_key)

        # Derive a 256-bit AES key using HKDF
        self.shared_encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=None,
            info=b'ecdh-secure-messaging-v1',
        ).derive(shared_secret)

        print(f"[{self.name}] Established shared encryption key")
        print(f"[{self.name}] Key (hex): {self.shared_encryption_key.hex()}")

    def encrypt_message(self, plaintext):
        """
        Encrypt a message using AES-GCM

        Args:
            plaintext: Message to encrypt (string)

        Returns:
            tuple: (nonce, ciphertext) where both are bytes
        """
        if self.shared_encryption_key is None:
            raise ValueError("No shared key established. Exchange public keys first.")

        # Convert string to bytes if necessary
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Generate a random 96-bit nonce (recommended for AES-GCM)
        nonce = os.urandom(12)

        # Create AES-GCM cipher
        aesgcm = AESGCM(self.shared_encryption_key)

        # Encrypt (includes authentication tag)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        print(f"[{self.name}] Encrypted message (length: {len(plaintext)} bytes)")

        return nonce, ciphertext

    def decrypt_message(self, nonce, ciphertext):
        """
        Decrypt a message using AES-GCM

        Args:
            nonce: The nonce used for encryption
            ciphertext: The encrypted message

        Returns:
            str: Decrypted plaintext message
        """
        if self.shared_encryption_key is None:
            raise ValueError("No shared key established. Exchange public keys first.")

        # Create AES-GCM cipher
        aesgcm = AESGCM(self.shared_encryption_key)

        # Decrypt and verify authentication tag
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            print(f"[{self.name}] Successfully decrypted message")
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"[{self.name}] Decryption failed: {e}")
            raise


def main():
    """Demonstrate secure messaging between Alice and Bob"""

    print("=" * 70)
    print("ECDH SECURE MESSAGING DEMONSTRATION")
    print("=" * 70)
    print()

    # --- Step 1: Initialize messengers ---
    print("STEP 1: Initializing Alice and Bob")
    print("-" * 70)
    alice = SecureMessenger("Alice")
    bob = SecureMessenger("Bob")
    print()

    # --- Step 2: Exchange public keys ---
    print("STEP 2: Public Key Exchange")
    print("-" * 70)
    alice_pub = alice.get_public_key_bytes()
    bob_pub = bob.get_public_key_bytes()

    print(f"[Alice] Sending public key to Bob...")
    print(f"[Bob] Sending public key to Alice...")
    print()

    # --- Step 3: Derive shared keys ---
    print("STEP 3: Deriving Shared Encryption Keys")
    print("-" * 70)
    alice.receive_peer_public_key(bob_pub)
    bob.receive_peer_public_key(alice_pub)
    print()

    # Verify both derived the same key
    if alice.shared_encryption_key == bob.shared_encryption_key:
        print("SUCCESS: Both parties derived the same encryption key!")
    else:
        print("ERROR: Keys don't match!")
        return
    print()

    # --- Step 4: Secure messaging ---
    print("STEP 4: Encrypted Messaging")
    print("-" * 70)

    # Alice sends a message to Bob
    message1 = "Hello Bob! This is a secret message from Alice."
    print(f"[Alice] Original message: '{message1}'")
    nonce1, ciphertext1 = alice.encrypt_message(message1)
    print(f"[Alice] Ciphertext (hex): {ciphertext1.hex()}")
    print(f"[Alice] Sending encrypted message to Bob...")
    print()

    # Bob receives and decrypts
    decrypted1 = bob.decrypt_message(nonce1, ciphertext1)
    print(f"[Bob] Decrypted message: '{decrypted1}'")
    print()

    # Bob replies to Alice
    message2 = "Hi Alice! I got your message. ECDH works great!"
    print(f"[Bob] Original message: '{message2}'")
    nonce2, ciphertext2 = bob.encrypt_message(message2)
    print(f"[Bob] Ciphertext (hex): {ciphertext2.hex()}")
    print(f"[Bob] Sending encrypted message to Alice...")
    print()

    # Alice receives and decrypts
    decrypted2 = alice.decrypt_message(nonce2, ciphertext2)
    print(f"[Alice] Decrypted message: '{decrypted2}'")
    print()

    # --- Step 5: Demonstrate message integrity ---
    print("STEP 5: Demonstrating Message Integrity (Authentication)")
    print("-" * 70)
    print("[Attempting to tamper with ciphertext...]")

    # Create a new message
    message3 = "This message will be tampered with."
    nonce3, ciphertext3 = alice.encrypt_message(message3)

    # Tamper with the ciphertext (flip one bit)
    tampered_ciphertext = bytearray(ciphertext3)
    tampered_ciphertext[0] ^= 0x01  # Flip the first bit
    tampered_ciphertext = bytes(tampered_ciphertext)

    print(f"[Attacker] Modified ciphertext: {tampered_ciphertext.hex()}")
    print(f"[Bob] Attempting to decrypt tampered message...")

    try:
        bob.decrypt_message(nonce3, tampered_ciphertext)
        print("[ERROR] Tampered message was accepted! (This shouldn't happen)")
    except Exception as e:
        print(f"[Bob] Decryption failed as expected - message integrity verified!")
        print(f"[Bob] Error: Authentication tag verification failed")
    print()

    # --- Step 6: Multiple messages ---
    print("STEP 6: Multiple Secure Messages")
    print("-" * 70)

    messages = [
        "Message 1: The quick brown fox jumps over the lazy dog.",
        "Message 2: ECDH provides perfect forward secrecy.",
        "Message 3: Each message uses a unique nonce for security.",
    ]

    for msg in messages:
        nonce, ciphertext = alice.encrypt_message(msg)
        decrypted = bob.decrypt_message(nonce, ciphertext)
        print(f"Original:  {msg}")
        print(f"Decrypted: {decrypted}")
        print(f"Match: {msg == decrypted}")
        print()

if __name__ == "__main__":
    main()

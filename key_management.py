#!/usr/bin/env python3
"""
Created by Tanmay Patil
Copyright © 2025 Tanmay Patil. All rights reserved.

This module provides key management functions for generating and saving keys.
It supports ECC key pairs, random symmetric keys, and PostQuantum key pairs (Ed25519 via PyNaCl).
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import logging
from pathlib import Path

class KeyManager:
    def __init__(self):
        self.salt_length = 32
        self.iteration_count = 100000
        self.key_length = 32

    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt."""
        return secrets.token_bytes(self.salt_length)

    def derive_key(self, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        if salt is None:
            salt = self.generate_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=self.key_length,
            salt=salt,
            iterations=self.iteration_count
        )
        key = kdf.derive(password.encode())
        return key, salt

    def generate_ecc_key_pair(self) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_symmetric_key(self) -> bytes:
        return secrets.token_bytes(self.key_length)

    def generate_pq_key_pair(self) -> tuple[bytes, bytes]:
        from nacl.signing import SigningKey
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        return signing_key.encode(), verify_key.encode()

    def save_key(self, key, path: str, password: str = None) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        from cryptography.hazmat.primitives.asymmetric import ec
        if isinstance(key, bytes):
            with open(path, "w") as f:
                f.write(key.hex())
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption_algorithm = serialization.NoEncryption()
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            with open(path, "wb") as f:
                f.write(pem)
        elif hasattr(key, "public_bytes"):
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(path, "wb") as f:
                f.write(pem)
        else:
            with open(path, "w") as f:
                f.write(key.hex())
        logging.info(f"Successfully saved key to {path}")

    def load_key(self, path: str, password: str = None) -> ec.EllipticCurvePrivateKey:
        with open(path, 'rb') as f:
            pem_data = f.read()
        if password:
            key = serialization.load_pem_private_key(pem_data, password=password.encode())
        else:
            key = serialization.load_pem_private_key(pem_data, password=None)
        if not hasattr(key, "private_bytes"):
            raise ValueError("Loaded key is not an ECC private key")
        return key

    def verify_key(self, key: bytes, expected_length: int = None) -> bool:
        if expected_length is None:
            expected_length = self.key_length
        if not isinstance(key, bytes) or len(key) != expected_length:
            return False
        if len(set(key)) < expected_length // 2:
            return False
        return True

    def sign_data(self, data: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, data: bytes, signature: bytes, public_key) -> bool:
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

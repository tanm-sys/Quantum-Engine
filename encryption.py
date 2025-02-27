#!/usr/bin/env python3
"""
This module handles file encryption and decryption operations.

Improved Features:
- Uses integrated authenticated encryption modes:
    • For AES (and legacy "AESGCM"), uses AESGCM mode (no CBC+HMAC).
    • For CHACHA20, uses ChaCha20Poly1305.
- Supports POSTQUANTUM (via PyNaCl SecretBox) and RSA-OAEP.
- Supports dynamic chunk-size tuning.
- Includes ProcessPoolExecutor–friendly helper functions.
"""

import os
import gzip
import tempfile
from pathlib import Path
from typing import Tuple, Optional

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM

# Define default chunk sizes.
DEFAULT_CHUNK_SIZE = 64 * 1024      # 64 KB for small files
LARGE_FILE_CHUNK_SIZE = 1024 * 1024  # 1 MB for large files

# Note: Integrated AE modes are used exclusively.
class EncryptionHandler:
    ITERATION_COUNT = 100000
    KEY_LENGTH = 32
    SALT_LENGTH = 16

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        pwd = password.encode("utf-8")
        key = PBKDF2(pwd, salt, dkLen=EncryptionHandler.KEY_LENGTH,
                     count=EncryptionHandler.ITERATION_COUNT, hmac_hash_module=SHA256)
        return key

    @staticmethod
    def encrypt_file(in_filename: str, out_filename: str, password: str,
                     algorithm: str, compress: bool = False, chunk_size: int = None) -> None:
        algorithm = algorithm.upper()
        # Read file content and optionally compress.
        with open(in_filename, "rb") as infile:
            plaintext = infile.read()
        if compress:
            plaintext = gzip.compress(plaintext)
        # Choose chunk size based on total data size.
        cs = chunk_size if chunk_size is not None else (LARGE_FILE_CHUNK_SIZE if len(plaintext) > 1024*1024 else DEFAULT_CHUNK_SIZE)

        if algorithm in ["AESGCM", "AES"]:  # treat "AES" as AESGCM now
            salt = get_random_bytes(EncryptionHandler.SALT_LENGTH)
            key = EncryptionHandler._derive_key(password, salt)
            aesgcm = AESGCM(key)
            nonce = get_random_bytes(12)
            # Encrypt the full plaintext at once (streaming could be implemented with chunked AE if needed)
            ct = aesgcm.encrypt(nonce, plaintext, None)
            with open(out_filename, "wb") as outfile:
                outfile.write(salt + nonce + ct)
        elif algorithm == "CHACHA20":
            salt = get_random_bytes(EncryptionHandler.SALT_LENGTH)
            key = EncryptionHandler._derive_key(password, salt)
            aead = ChaCha20Poly1305(key)
            nonce = get_random_bytes(12)
            ct = aead.encrypt(nonce, plaintext, None)
            with open(out_filename, "wb") as outfile:
                outfile.write(salt + nonce + ct)
        elif algorithm == "POSTQUANTUM":
            # Using PyNaCl's SecretBox as a placeholder.
            from nacl.secret import SecretBox
            salt = get_random_bytes(EncryptionHandler.SALT_LENGTH)
            key = PBKDF2(password.encode("utf-8"), salt, dkLen=32,
                         count=EncryptionHandler.ITERATION_COUNT, hmac_hash_module=SHA256)
            from nacl.utils import random as nacl_random
            box = SecretBox(key)
            ct = box.encrypt(plaintext)
            with open(out_filename, "wb") as outfile:
                outfile.write(salt + ct)
        elif algorithm == "RSAOAEP":
            from Crypto.PublicKey import RSA
            from Crypto.Cipher import PKCS1_OAEP
            # Generate a random symmetric key and encrypt the file using AESGCM.
            sym_key = get_random_bytes(EncryptionHandler.KEY_LENGTH)
            salt = get_random_bytes(EncryptionHandler.SALT_LENGTH)
            key = AESGCM(sym_key)  # Note: here we use symmetric key directly
            nonce = get_random_bytes(12)
            ct = AESGCM(sym_key).encrypt(nonce, plaintext, None)
            rsa_pub_path = input("Enter path to RSA public key file for RSA-OAEP: ")
            with open(rsa_pub_path, "rb") as f:
                rsa_key = RSA.import_key(f.read())
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            enc_sym_key = cipher_rsa.encrypt(sym_key)
            with open(out_filename, "wb") as outfile:
                outfile.write(salt + nonce + len(enc_sym_key).to_bytes(4, byteorder="big") + enc_sym_key + ct)
        else:
            raise ValueError("Unsupported algorithm.")

    @staticmethod
    def decrypt_file(in_filename: str, out_filename: str, password: str,
                     algorithm: str, compress: bool = False, chunk_size: int = None) -> None:
        algorithm = algorithm.upper()
        if algorithm in ["AESGCM", "AES"]:
            with open(in_filename, "rb") as infile:
                salt = infile.read(EncryptionHandler.SALT_LENGTH)
                key = EncryptionHandler._derive_key(password, salt)
                nonce = infile.read(12)
                ct = infile.read()
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ct, None)
            if compress:
                plaintext = gzip.decompress(plaintext)
            with open(out_filename, "wb") as outfile:
                outfile.write(plaintext)
        elif algorithm == "CHACHA20":
            with open(in_filename, "rb") as infile:
                salt = infile.read(EncryptionHandler.SALT_LENGTH)
                key = EncryptionHandler._derive_key(password, salt)
                nonce = infile.read(12)
                ct = infile.read()
            aead = ChaCha20Poly1305(key)
            plaintext = aead.decrypt(nonce, ct, None)
            if compress:
                plaintext = gzip.decompress(plaintext)
            with open(out_filename, "wb") as outfile:
                outfile.write(plaintext)
        elif algorithm == "POSTQUANTUM":
            from nacl.secret import SecretBox
            from nacl.exceptions import CryptoError
            with open(in_filename, "rb") as infile:
                salt = infile.read(EncryptionHandler.SALT_LENGTH)
                ct = infile.read()
            key = PBKDF2(password.encode("utf-8"), salt, dkLen=32,
                         count=EncryptionHandler.ITERATION_COUNT, hmac_hash_module=SHA256)
            box = SecretBox(key)
            try:
                plaintext = box.decrypt(ct)
            except CryptoError as e:
                raise ValueError("Decryption failed. Check your password and settings.") from e
            if compress:
                plaintext = gzip.decompress(plaintext)
            with open(out_filename, "wb") as outfile:
                outfile.write(plaintext)
        elif algorithm == "RSAOAEP":
            from Crypto.PublicKey import RSA
            from Crypto.Cipher import PKCS1_OAEP
            with open(in_filename, "rb") as infile:
                salt = infile.read(EncryptionHandler.SALT_LENGTH)
                nonce = infile.read(12)
                key_len = int.from_bytes(infile.read(4), byteorder="big")
                enc_sym_key = infile.read(key_len)
                ct = infile.read()
            rsa_priv_path = input("Enter path to RSA private key file for RSA-OAEP: ")
            with open(rsa_priv_path, "rb") as f:
                rsa_key = RSA.import_key(f.read())
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            sym_key = cipher_rsa.decrypt(enc_sym_key)
            plaintext = AESGCM(sym_key).decrypt(nonce, ct, None)
            if compress:
                plaintext = gzip.decompress(plaintext)
            with open(out_filename, "wb") as outfile:
                outfile.write(plaintext)
        else:
            raise ValueError("Unsupported algorithm.")

    @staticmethod
    def rotate_key_file(in_filename: str, out_filename: str, old_password: str, new_password: str,
                        algorithm: str, compress: bool = False, chunk_size: int = None) -> None:
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_name = temp_file.name
            EncryptionHandler.decrypt_file(in_filename, temp_name, old_password, algorithm, compress, chunk_size)
            EncryptionHandler.encrypt_file(temp_name, out_filename, new_password, algorithm, compress, chunk_size)
        finally:
            if temp_name and os.path.exists(temp_name):
                os.remove(temp_name)

# Helper functions for ProcessPoolExecutor usage.
def process_file(action: str, file_path: str, output_path: Optional[str],
                 password: str, algorithm: str, compress: bool, chunk_size: int,
                 policy: dict = None) -> None:
    # Apply policy if provided (policy processing could change algorithm choice)
    if policy:
        from utils import apply_encryption_policy
        algorithm = apply_encryption_policy(file_path, algorithm, policy)
    if output_path is None:
        suffix = ".encrypted" if action in ["encrypt", "rotate-key"] else ".decrypted"
        output_path = str(Path(file_path).with_suffix(suffix))
    if action == "encrypt":
        EncryptionHandler.encrypt_file(file_path, output_path, password, algorithm, compress, chunk_size)
    elif action == "decrypt":
        EncryptionHandler.decrypt_file(file_path, output_path, password, algorithm, compress, chunk_size)
    elif action == "rotate-key":
        new_password = input("Enter new password for key rotation: ")
        EncryptionHandler.rotate_key_file(file_path, output_path, password, new_password, algorithm, compress, chunk_size)
    else:
        raise ValueError("Unsupported file operation.")

def process_directory(action: str, dir_path: str, output_dir: Optional[str],
                      password: str, algorithm: str, compress: bool, chunk_size: int,
                      policy: dict = None) -> None:
    from encryption import process_file
    files = list(Path(dir_path).rglob("*"))
    files = [f for f in files if f.is_file()]
    for file in files:
        rel_path = file.relative_to(dir_path)
        out_file = Path(output_dir) / rel_path if output_dir else file.with_suffix(".encrypted" if action in ["encrypt", "rotate-key"] else ".decrypted")
        out_file.parent.mkdir(parents=True, exist_ok=True)
        process_file(action, str(file), str(out_file), password, algorithm, compress, chunk_size, policy)

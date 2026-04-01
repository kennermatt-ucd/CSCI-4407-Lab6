"""
Task 2 – AES-CBC Encryption
Encrypt a message with AES-CBC and decrypt it to verify confidentiality.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

MESSAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "messages")
PLAINTEXT_FILE = os.path.join(MESSAGE_DIR, "message1.txt")


def pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(pad(plaintext)) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return unpad(decryptor.update(ciphertext) + decryptor.finalize())


def main():
    key = os.urandom(32)   # AES-256
    iv  = os.urandom(16)

    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext = aes_cbc_encrypt(key, iv, plaintext)
    decrypted  = aes_cbc_decrypt(key, iv, ciphertext)

    print("=== Task 2: AES-CBC ===\n")
    print(f"Key        : {key.hex()}")
    print(f"IV         : {iv.hex()}")
    print(f"Ciphertext : {ciphertext.hex()}")
    print(f"Decrypted  : {decrypted.decode()}")
    assert decrypted == plaintext, "Decryption mismatch!"
    print("Decryption successful.")


if __name__ == "__main__":
    main()

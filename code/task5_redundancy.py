"""
Task 5 – Redundancy Check
Append a known redundancy value to the plaintext before encryption and verify
it after decryption to detect tampering (naive integrity).
"""

import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE

REDUNDANCY = b"VERIFY_OK"


def encrypt_with_redundancy(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return aes_cbc_encrypt(key, iv, plaintext + REDUNDANCY)


def decrypt_and_verify(key: bytes, iv: bytes, ciphertext: bytes) -> tuple[bytes, bool]:
    decrypted = aes_cbc_decrypt(key, iv, ciphertext)
    if decrypted.endswith(REDUNDANCY):
        return decrypted[: -len(REDUNDANCY)], True
    return decrypted, False


def main():
    key = os.urandom(32)
    iv  = os.urandom(16)

    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext            = encrypt_with_redundancy(key, iv, plaintext)
    recovered, is_valid   = decrypt_and_verify(key, iv, ciphertext)

    print("=== Task 5: Redundancy ===\n")
    print(f"Redundancy value : {REDUNDANCY!r}")
    print(f"Integrity check  : {'PASS' if is_valid else 'FAIL'}")
    print(f"Recovered text   : {recovered!r}")


if __name__ == "__main__":
    main()

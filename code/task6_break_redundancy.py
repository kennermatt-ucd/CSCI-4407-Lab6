"""
Task 6 – Break Redundancy
Perform ≥3 tampering attempts against the redundancy scheme and show that an
attacker can bypass the check, proving redundancy alone is insecure.
"""

import os
from task5_redundancy import (
    encrypt_with_redundancy,
    decrypt_and_verify,
    REDUNDANCY,
    PLAINTEXT_FILE,
)
from task2_aes_cbc import aes_cbc_encrypt


def tamper_ciphertext(ciphertext: bytes, index: int, mask: int = 0xFF) -> bytes:
    ct = bytearray(ciphertext)
    ct[index] ^= mask
    return bytes(ct)


def main():
    key = os.urandom(32)
    iv  = os.urandom(16)

    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext = encrypt_with_redundancy(key, iv, plaintext)

    tampering_attempts = [
        ("Flip byte 0",  tamper_ciphertext(ciphertext, 0)),
        ("Flip byte 8",  tamper_ciphertext(ciphertext, 8)),
        ("Flip byte 16", tamper_ciphertext(ciphertext, 16)),
        # Add more creative attempts here
    ]

    print("=== Task 6: Break Redundancy ===\n")
    for label, tampered in tampering_attempts:
        _, is_valid = decrypt_and_verify(key, iv, tampered)
        print(f"{label:20s} → {'PASS (not detected)' if is_valid else 'FAIL (detected)'}")

    print("\nConclusion: explain here why redundancy alone is cryptographically insecure.")


if __name__ == "__main__":
    main()

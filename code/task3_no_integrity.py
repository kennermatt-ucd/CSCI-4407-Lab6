"""
Task 3 – No Integrity
Modify a ciphertext byte and show that AES-CBC still decrypts without error,
demonstrating that CBC alone provides no integrity guarantee.
"""

import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE


def tamper(ciphertext: bytes, byte_index: int = 0) -> bytes:
    ct = bytearray(ciphertext)
    ct[byte_index] ^= 0xFF   # flip all bits in one byte
    return bytes(ct)


def main():
    key = os.urandom(32)
    iv  = os.urandom(16)

    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext        = aes_cbc_encrypt(key, iv, plaintext)
    tampered_ct       = tamper(ciphertext)
    decrypted_tampered = aes_cbc_decrypt(key, iv, tampered_ct)

    print("=== Task 3: No Integrity ===\n")
    print(f"Original ciphertext : {ciphertext.hex()}")
    print(f"Tampered ciphertext : {tampered_ct.hex()}")
    print(f"Decrypted (tampered): {decrypted_tampered!r}")
    print("\nObservation: decryption succeeded despite tampering — no integrity check.")


if __name__ == "__main__":
    main()

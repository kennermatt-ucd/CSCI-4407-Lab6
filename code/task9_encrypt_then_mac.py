"""
Task 9 – Encrypt-then-MAC  (CRITICAL)
The correct construction: encrypt first, then MAC over the ciphertext.
Verify the tag BEFORE decryption.
"""

import hmac
import hashlib
import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE


def encrypt_then_mac(
    enc_key: bytes, mac_key: bytes, iv: bytes, plaintext: bytes
) -> tuple[bytes, bytes]:
    ciphertext = aes_cbc_encrypt(enc_key, iv, plaintext)
    tag        = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return ciphertext, tag


def verify_then_decrypt(
    enc_key: bytes, mac_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes
) -> bytes | None:
    # CRITICAL: verify tag BEFORE any decryption
    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        return None
    return aes_cbc_decrypt(enc_key, iv, ciphertext)


def tamper_ciphertext(ciphertext: bytes, index: int = 0) -> bytes:
    ct = bytearray(ciphertext)
    ct[index] ^= 0xFF
    return bytes(ct)


def tamper_tag(tag: bytes, index: int = 0) -> bytes:
    t = bytearray(tag)
    t[index] ^= 0xFF
    return bytes(t)


def main():
    enc_key = os.urandom(32)
    mac_key = os.urandom(32)
    iv      = os.urandom(16)

    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext, tag = encrypt_then_mac(enc_key, mac_key, iv, plaintext)

    print("=== Task 9: Encrypt-then-MAC ===\n")

    # Case 1: valid
    result = verify_then_decrypt(enc_key, mac_key, iv, ciphertext, tag)
    print(f"Valid case            → {'PASS' if result is not None else 'FAIL'}: {result!r}")

    # Case 2: tampered ciphertext
    result_ct = verify_then_decrypt(enc_key, mac_key, iv, tamper_ciphertext(ciphertext), tag)
    print(f"Ciphertext tampered   → {'PASS (not detected!)' if result_ct is not None else 'FAIL (rejected)'}")

    # Case 3: tampered tag
    result_tag = verify_then_decrypt(enc_key, mac_key, iv, ciphertext, tamper_tag(tag))
    print(f"Tag tampered          → {'PASS (not detected!)' if result_tag is not None else 'FAIL (rejected)'}")

    print("\nExplain: why Encrypt-then-MAC achieves INT-CTXT security.")


if __name__ == "__main__":
    main()

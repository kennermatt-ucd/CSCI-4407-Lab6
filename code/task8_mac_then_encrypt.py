"""
Task 8 – MAC-then-Encrypt
Compute a MAC over the plaintext, append it, then encrypt the whole thing.
Demonstrate both the valid and tampered cases.
"""

import hmac
import hashlib
import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE

MAC_SIZE = 32   # SHA-256 output bytes


def mac_then_encrypt(
    enc_key: bytes, mac_key: bytes, iv: bytes, plaintext: bytes
) -> bytes:
    tag        = hmac.new(mac_key, plaintext, hashlib.sha256).digest()
    ciphertext = aes_cbc_encrypt(enc_key, iv, plaintext + tag)
    return ciphertext


def decrypt_then_verify(
    enc_key: bytes, mac_key: bytes, iv: bytes, ciphertext: bytes
) -> bytes | None:
    decrypted = aes_cbc_decrypt(enc_key, iv, ciphertext)
    plaintext, received_tag = decrypted[:-MAC_SIZE], decrypted[-MAC_SIZE:]
    expected_tag = hmac.new(mac_key, plaintext, hashlib.sha256).digest()
    if hmac.compare_digest(received_tag, expected_tag):
        return plaintext
    return None


def tamper(ciphertext: bytes, index: int = 0) -> bytes:
    ct = bytearray(ciphertext)
    ct[index] ^= 0xFF
    return bytes(ct)


def main():
    enc_key = os.urandom(32)
    mac_key = os.urandom(32)
    iv      = os.urandom(16)

    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext = mac_then_encrypt(enc_key, mac_key, iv, plaintext)

    # Valid case
    recovered = decrypt_then_verify(enc_key, mac_key, iv, ciphertext)
    print("=== Task 8: MAC-then-Encrypt ===\n")
    print(f"Valid case   → {'PASS' if recovered is not None else 'FAIL'}: {recovered!r}")

    # Tampered case
    tampered_ct       = tamper(ciphertext)
    recovered_tampered = decrypt_then_verify(enc_key, mac_key, iv, tampered_ct)
    print(f"Tampered case → {'PASS (not detected!)' if recovered_tampered is not None else 'FAIL (detected)'}")
    print("\nExplain: why does composition order affect security?")


if __name__ == "__main__":
    main()

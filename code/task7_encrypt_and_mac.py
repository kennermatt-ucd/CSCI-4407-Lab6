"""
Task 7 – Encrypt-and-MAC
Encrypt the plaintext with AES-CBC and compute a MAC over the plaintext
independently (not over the ciphertext).
"""

import hmac
import hashlib
import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE


def encrypt_and_mac(
    enc_key: bytes, mac_key: bytes, iv: bytes, plaintext: bytes
) -> tuple[bytes, bytes]:
    ciphertext = aes_cbc_encrypt(enc_key, iv, plaintext)
    tag = hmac.new(mac_key, plaintext, hashlib.sha256).digest()
    return ciphertext, tag


def verify_and_decrypt(
    enc_key: bytes, mac_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes
) -> bytes | None:
    decrypted = aes_cbc_decrypt(enc_key, iv, ciphertext)
    expected  = hmac.new(mac_key, decrypted, hashlib.sha256).digest()
    if hmac.compare_digest(tag, expected):
        return decrypted
    return None


def main():
    enc_key = os.urandom(32)
    mac_key = os.urandom(32)
    iv      = os.urandom(16)

    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext, tag = encrypt_and_mac(enc_key, mac_key, iv, plaintext)
    recovered       = verify_and_decrypt(enc_key, mac_key, iv, ciphertext, tag)

    print("=== Task 7: Encrypt-and-MAC ===\n")
    print(f"Ciphertext : {ciphertext.hex()}")
    print(f"MAC tag    : {tag.hex()}")
    print(f"Verified   : {'YES' if recovered is not None else 'NO'}")
    print(f"Recovered  : {recovered!r}")
    print("\nWeakness: the MAC is over the plaintext, not the ciphertext — explain implications.")


if __name__ == "__main__":
    main()

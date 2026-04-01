"""
Task 4 – CBC Bit-Flipping Attack
Demonstrate that flipping a bit in ciphertext block N causes a predictable,
controlled change in the decrypted plaintext of block N+1.
"""

import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE


def bit_flip_attack(ciphertext: bytes, target_byte: int, xor_mask: int) -> bytes:
    """Flip `target_byte` in the ciphertext using `xor_mask`."""
    ct = bytearray(ciphertext)
    ct[target_byte] ^= xor_mask
    return bytes(ct)


def main():
    key = os.urandom(32)
    iv  = os.urandom(16)

    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext = aes_cbc_encrypt(key, iv, plaintext)

    # TODO: choose a target byte index and XOR mask that produce a
    # meaningful change in the second plaintext block.
    target_byte = 0
    xor_mask    = 0x01

    flipped_ct       = bit_flip_attack(ciphertext, target_byte, xor_mask)
    decrypted_flipped = aes_cbc_decrypt(key, iv, flipped_ct)

    print("=== Task 4: Bit-Flipping Attack ===\n")
    print(f"Original plaintext : {plaintext!r}")
    print(f"Decrypted (flipped): {decrypted_flipped!r}")
    print("\nObservation: a single-bit change in the ciphertext altered the plaintext predictably.")


if __name__ == "__main__":
    main()

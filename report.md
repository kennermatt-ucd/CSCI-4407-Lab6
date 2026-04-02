# Lab 6 — Group 10 — Authenticated Encryption

**Course:** CSCI/CSCY 4407 — Security & Cryptography
**Semester:** Spring 2026
**Group Members:** Cassius Kemp, Matthew Kenner, Jonathan Le

---

## Task 1 — Setup

### Overview

This task creates the working directory structure and two plaintext message files used throughout
the lab. Each file is hashed with SHA-256 to establish a baseline fingerprint, allowing us to
detect any unintended modification to the source messages across tasks.

### Source Code

```python
"""
Task 1 – Setup
Create message files and display their SHA256 hashes.
"""

import hashlib
import os

MESSAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "messages")


def sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    files = sorted(
        os.path.join(MESSAGE_DIR, fn)
        for fn in os.listdir(MESSAGE_DIR)
        if fn.endswith(".txt")
    )

    print("=== Task 1: Setup ===\n")
    for path in files:
        digest = sha256_file(path)
        print(f"File : {os.path.basename(path)}")
        print(f"SHA256: {digest}\n")


if __name__ == "__main__":
    main()
```

### Steps

**Step 1 — Verify message files exist and inspect their contents**

```bash
cd /mnt/d/Development/School/Security&Crypto/CSCI-4407-Lab6
ls messages/
cat messages/message1.txt
cat messages/message2.txt
```

Two plaintext files serve as the test messages for all subsequent encryption tasks.

**Step 2 — Run the setup script to display SHA-256 hashes**

```bash
python code/task1_setup.py
```

The script reads each `.txt` file in the `messages/` directory, computes its SHA-256 digest,
and prints the filename alongside the hex digest. These hashes act as a reference integrity
baseline.

### Screenshots

**Screenshot 1 — Directory listing and message file contents**

![alt text](screenshots/task0.1.png)
![alt text](screenshots/task0.2.png)

*What to observe:* Both message files are present and contain the expected plaintext strings.

**Screenshot 2 — `task1_setup.py` terminal output**

![alt text](screenshots/task1.png)

*What to observe:* Each file produces a distinct 64-character (256-bit) hex digest. Even though
the messages are similar, the hashes are completely different, illustrating the hash function's
sensitivity to input differences.

### Results

| File         | SHA-256 Digest                                                   |
|--------------|------------------------------------------------------------------|
| message1.txt | 561f65870c36b11746715e4ff15587ef89c9222017cf96fede09bae7058fae90                                       |
| message2.txt | 7db83f660e59c58d325a3fe3d1a2f729d0029008b3489a5f6d4ba4d2999cd77b                                       |

### Explanation

SHA-256 provides a fixed-length fingerprint for any input. By hashing the message files before
any encryption, we can verify their integrity at any point. This step also confirms that the
lab environment is correctly set up with the `cryptography` library available for later tasks.

---

## Task 2 — AES-CBC Encryption

### Overview

AES-CBC (Cipher Block Chaining) mode provides **confidentiality** — it transforms plaintext into
ciphertext that is computationally infeasible to read without the key. This task demonstrates
correct AES-256-CBC encryption and decryption using a random key and IV.

### Source Code

```python
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
```

### Steps

**Step 1 — Run the AES-CBC script**

```bash
python code/task2_aes_cbc.py
```

The script generates a fresh 256-bit key and 128-bit IV using `os.urandom`, encrypts
`message1.txt`, then decrypts the ciphertext and asserts the result matches the original.

### Screenshots

**Screenshot 1 — `task2_aes_cbc.py` terminal output**

![alt text](screenshots/task2.png)

*What to observe:* The key and IV are random 32- and 16-byte hex strings respectively. The
ciphertext is a block-aligned hex string with no visible relationship to the plaintext.
The decrypted output matches the original message exactly, confirmed by the assertion.

### Results

| Field       | Value                          |
|-------------|--------------------------------|
| Key (hex)   | 88d11280c01ec3641ef624be523db5b0e933ec7760a20976a1e5571fca36de5 |
| IV (hex)    | 77f226d5dfeccf9a7380fbeb6b0aad3 |
| Ciphertext  | af1a87f5362511895df53046f8f23c0d66515d2fd896d48a4355b7517bfcfa85fc9c7bac15002586675489d185b4c1b603b136a4707a125d36a50880713040 |
| Decrypted   | This is message 1 for the authenticated encryption lab.  |

### Explanation

AES-CBC provides **confidentiality** by chaining each plaintext block with the previous
ciphertext block before encryption. This means identical plaintext blocks produce different
ciphertext blocks, preventing pattern leakage. However, CBC alone provides **no integrity
guarantee** — an attacker can modify ciphertext bytes without triggering any error, as
demonstrated in Task 3. A separate authentication mechanism is required for full security.

---

## Task 3 — No Integrity

### Overview

This task demonstrates that AES-CBC provides no integrity protection. A single byte of the
ciphertext is flipped; decryption still completes without error, producing garbled output.
This proves that confidentiality and integrity are separate properties.

### Source Code

```python
"""
Task 3 – No Integrity
Modify a ciphertext byte and show that AES-CBC still decrypts without error.
"""

import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE


def tamper(ciphertext: bytes, byte_index: int = 0) -> bytes:
    ct = bytearray(ciphertext)
    ct[byte_index] ^= 0xFF
    return bytes(ct)


def main():
    key = os.urandom(32)
    iv  = os.urandom(16)

    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext         = aes_cbc_encrypt(key, iv, plaintext)
    tampered_ct        = tamper(ciphertext)
    decrypted_tampered = aes_cbc_decrypt(key, iv, tampered_ct)

    print("=== Task 3: No Integrity ===\n")
    print(f"Original ciphertext : {ciphertext.hex()}")
    print(f"Tampered ciphertext : {tampered_ct.hex()}")
    print(f"Decrypted (tampered): {decrypted_tampered!r}")
    print("\nObservation: decryption succeeded despite tampering — no integrity check.")


if __name__ == "__main__":
    main()
```

### Steps

**Step 1 — Run the no-integrity script**

```bash
python code/task3_no_integrity.py
```

### Screenshots

**Screenshot 1 — `task3_no_integrity.py` terminal output**

<!-- Insert screenshot: terminal showing original ciphertext, tampered ciphertext, and the garbled decrypted output -->

*What to observe:* The original and tampered ciphertexts differ in exactly one byte. Decryption
completes with no exception, but the recovered plaintext is corrupted — proving AES-CBC has no
built-in integrity check.

### Explanation

In CBC mode, flipping a bit in ciphertext block *N* has two effects on decryption: block *N*
decrypts to garbage (randomized), and the corresponding bit in block *N+1* is predictably
flipped. The decryption function has no way to detect this tampering because AES-CBC carries
no authentication tag. An attacker can silently corrupt messages in transit.

---

## Task 4 — CBC Bit-Flipping Attack

### Overview

The bit-flipping attack exploits the CBC XOR chain to make a **controlled, predictable**
change to the decrypted plaintext by modifying a byte in the preceding ciphertext block.

### Source Code

```python
"""
Task 4 – CBC Bit-Flipping Attack
"""

import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE


def bit_flip_attack(ciphertext: bytes, target_byte: int, xor_mask: int) -> bytes:
    ct = bytearray(ciphertext)
    ct[target_byte] ^= xor_mask
    return bytes(ct)


def main():
    key = os.urandom(32)
    iv  = os.urandom(16)

    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext = aes_cbc_encrypt(key, iv, plaintext)

    target_byte = 0
    xor_mask    = 0x01

    flipped_ct        = bit_flip_attack(ciphertext, target_byte, xor_mask)
    decrypted_flipped = aes_cbc_decrypt(key, iv, flipped_ct)

    print("=== Task 4: Bit-Flipping Attack ===\n")
    print(f"Original plaintext : {plaintext!r}")
    print(f"Decrypted (flipped): {decrypted_flipped!r}")
    print("\nObservation: a single-bit change in the ciphertext altered the plaintext predictably.")


if __name__ == "__main__":
    main()
```

### Steps

**Step 1 — Run the bit-flip script**

```bash
python code/task4_bit_flip.py
```

### Screenshots

**Screenshot 1 — `task4_bit_flip.py` terminal output**

<!-- Insert screenshot: terminal showing original plaintext and the modified decrypted output side by side -->

*What to observe:* The original plaintext and the flipped decrypted output differ at a
predictable position. Block 1 of the decryption is corrupted (random-looking), while block 2
has the targeted bit flipped exactly as intended — demonstrating controlled plaintext manipulation.

### Explanation

In CBC decryption, block *i* of plaintext is computed as `AES_decrypt(C[i]) XOR C[i-1]`.
Flipping bit *j* of `C[i-1]` therefore flips bit *j* of `P[i]`. An attacker who knows
the plaintext layout can craft a precise modification — for example, changing a field value —
without knowing the key. This is the CBC malleability vulnerability, and it is the reason
authenticated encryption (not just encryption) is required for secure systems.

---

## Task 5 — Redundancy Check

### Overview

A naive attempt at integrity: append a known constant (`VERIFY_OK`) to the plaintext before
encrypting, then check for it after decryption. This task shows the idea works in the
untampered case but is easily defeated (see Task 6).

### Source Code

```python
"""
Task 5 – Redundancy Check
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

    ciphertext          = encrypt_with_redundancy(key, iv, plaintext)
    recovered, is_valid = decrypt_and_verify(key, iv, ciphertext)

    print("=== Task 5: Redundancy ===\n")
    print(f"Redundancy value : {REDUNDANCY!r}")
    print(f"Integrity check  : {'PASS' if is_valid else 'FAIL'}")
    print(f"Recovered text   : {recovered!r}")


if __name__ == "__main__":
    main()
```

### Steps

**Step 1 — Run the redundancy script**

```bash
python code/task5_redundancy.py
```

### Screenshots

**Screenshot 1 — `task5_redundancy.py` terminal output**

<!-- Insert screenshot: terminal showing redundancy value, PASS result, and recovered plaintext -->

*What to observe:* The integrity check reports PASS and the recovered text matches the original
message, confirming the scheme works when no tampering has occurred.

### Explanation

Appending a known sentinel value and checking for it after decryption can detect *random*
corruption with some probability, but it is not a cryptographic integrity mechanism. As shown
in Task 6, an attacker who knows the redundancy value can craft ciphertext modifications that
either preserve the sentinel or bypass the check entirely.

---

## Task 6 — Break Redundancy

### Overview

Three (or more) tampering attempts against the redundancy scheme from Task 5, demonstrating
that the check can be bypassed and is therefore cryptographically insecure.

### Source Code

```python
"""
Task 6 – Break Redundancy
"""

import os
from task5_redundancy import encrypt_with_redundancy, decrypt_and_verify, REDUNDANCY, PLAINTEXT_FILE
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
    ]

    print("=== Task 6: Break Redundancy ===\n")
    for label, tampered in tampering_attempts:
        _, is_valid = decrypt_and_verify(key, iv, tampered)
        print(f"{label:20s} → {'PASS (not detected)' if is_valid else 'FAIL (detected)'}")

    print("\nConclusion: redundancy alone is cryptographically insecure.")


if __name__ == "__main__":
    main()
```

### Steps

**Step 1 — Run the break-redundancy script**

```bash
python code/task6_break_redundancy.py
```

### Screenshots

**Screenshot 1 — `task6_break_redundancy.py` terminal output**

<!-- Insert screenshot: terminal showing results of all three tampering attempts (pass/fail per attempt) -->

*What to observe:* Some tampering attempts may pass (not detected) because the corruption lands
in the message body rather than the redundancy suffix. This shows the scheme cannot reliably
detect all tampering.

### Explanation

The redundancy check only inspects the last few bytes of the decrypted output. An attacker who
modifies bytes in the early ciphertext blocks corrupts only the message body — the redundancy
suffix survives intact and the check passes. Because the check is deterministic and its location
is known, it provides no security guarantee. A proper MAC uses a secret key and covers the
entire message, making selective forgery computationally infeasible.

---

## Task 7 — Encrypt-and-MAC

### Overview

Encrypt-and-MAC computes the MAC over the **plaintext** and the encryption independently,
then sends both. This is the weakest authenticated-encryption construction.

### Source Code

```python
"""
Task 7 – Encrypt-and-MAC
"""

import hmac
import hashlib
import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE


def encrypt_and_mac(enc_key, mac_key, iv, plaintext):
    ciphertext = aes_cbc_encrypt(enc_key, iv, plaintext)
    tag = hmac.new(mac_key, plaintext, hashlib.sha256).digest()
    return ciphertext, tag


def verify_and_decrypt(enc_key, mac_key, iv, ciphertext, tag):
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


if __name__ == "__main__":
    main()
```

### Steps

**Step 1 — Run the encrypt-and-MAC script**

```bash
python code/task7_encrypt_and_mac.py
```

### Screenshots

**Screenshot 1 — `task7_encrypt_and_mac.py` terminal output**

<!-- Insert screenshot: terminal showing ciphertext hex, MAC tag hex, Verified: YES, and recovered plaintext -->

*What to observe:* The valid case passes verification and recovers the original plaintext.

### Explanation

In Encrypt-and-MAC the tag authenticates the **plaintext**, not the ciphertext. This has two
weaknesses: (1) the tag may leak information about the plaintext since it is computed from it
directly, and (2) an attacker can modify the ciphertext without invalidating the tag, because
the tag is tied to the original plaintext. When the receiver decrypts the tampered ciphertext
and recomputes the MAC from the resulting garbage, it will not match — but the decryption has
already occurred, potentially exposing the receiver to chosen-ciphertext attacks.

---

## Task 8 — MAC-then-Encrypt

### Overview

MAC-then-Encrypt computes the MAC over the plaintext, appends it, then encrypts everything
together. Both valid and tampered cases are demonstrated.

### Source Code

```python
"""
Task 8 – MAC-then-Encrypt
"""

import hmac
import hashlib
import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE

MAC_SIZE = 32


def mac_then_encrypt(enc_key, mac_key, iv, plaintext):
    tag        = hmac.new(mac_key, plaintext, hashlib.sha256).digest()
    ciphertext = aes_cbc_encrypt(enc_key, iv, plaintext + tag)
    return ciphertext


def decrypt_then_verify(enc_key, mac_key, iv, ciphertext):
    decrypted = aes_cbc_decrypt(enc_key, iv, ciphertext)
    plaintext, received_tag = decrypted[:-MAC_SIZE], decrypted[-MAC_SIZE:]
    expected_tag = hmac.new(mac_key, plaintext, hashlib.sha256).digest()
    if hmac.compare_digest(received_tag, expected_tag):
        return plaintext
    return None


def tamper(ciphertext, index=0):
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

    recovered = decrypt_then_verify(enc_key, mac_key, iv, ciphertext)
    print("=== Task 8: MAC-then-Encrypt ===\n")
    print(f"Valid case    → {'PASS' if recovered is not None else 'FAIL'}: {recovered!r}")

    tampered_ct        = tamper(ciphertext)
    recovered_tampered = decrypt_then_verify(enc_key, mac_key, iv, tampered_ct)
    print(f"Tampered case → {'PASS (not detected!)' if recovered_tampered is not None else 'FAIL (detected)'}")


if __name__ == "__main__":
    main()
```

### Steps

**Step 1 — Run the MAC-then-Encrypt script**

```bash
python code/task8_mac_then_encrypt.py
```

### Screenshots

**Screenshot 1 — `task8_mac_then_encrypt.py` terminal output**

<!-- Insert screenshot: terminal showing valid case PASS and tampered case FAIL (detected) -->

*What to observe:* The valid case passes. The tampered case is detected (FAIL) because the
MAC covers the plaintext which is recovered after decryption — corruption in the ciphertext
propagates to the decrypted plaintext and breaks the tag comparison.

### Explanation

MAC-then-Encrypt hides the MAC inside the ciphertext, which is an improvement over
Encrypt-and-MAC. However, the receiver must **decrypt first** before verifying the MAC. This
means the decryption oracle is exposed to unverified ciphertext, making the scheme vulnerable
to padding-oracle attacks (e.g., BEAST, Lucky13 against TLS). The order of operations matters:
verification should happen on the ciphertext *before* any decryption work is done.

---

## Task 9 — Encrypt-then-MAC (CRITICAL)

### Overview

The correct construction: encrypt first, then compute the MAC over the ciphertext (and IV).
The tag is **verified before any decryption** occurs. Three cases are tested: valid, tampered
ciphertext, and tampered tag.

### Source Code

```python
"""
Task 9 – Encrypt-then-MAC (CRITICAL)
"""

import hmac
import hashlib
import os
from task2_aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt, PLAINTEXT_FILE


def encrypt_then_mac(enc_key, mac_key, iv, plaintext):
    ciphertext = aes_cbc_encrypt(enc_key, iv, plaintext)
    tag        = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return ciphertext, tag


def verify_then_decrypt(enc_key, mac_key, iv, ciphertext, tag):
    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        return None
    return aes_cbc_decrypt(enc_key, iv, ciphertext)


def tamper_ciphertext(ciphertext, index=0):
    ct = bytearray(ciphertext)
    ct[index] ^= 0xFF
    return bytes(ct)


def tamper_tag(tag, index=0):
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

    result = verify_then_decrypt(enc_key, mac_key, iv, ciphertext, tag)
    print(f"Valid case            → {'PASS' if result is not None else 'FAIL'}: {result!r}")

    result_ct = verify_then_decrypt(enc_key, mac_key, iv, tamper_ciphertext(ciphertext), tag)
    print(f"Ciphertext tampered   → {'PASS (not detected!)' if result_ct is not None else 'FAIL (rejected)'}")

    result_tag = verify_then_decrypt(enc_key, mac_key, iv, ciphertext, tamper_tag(tag))
    print(f"Tag tampered          → {'PASS (not detected!)' if result_tag is not None else 'FAIL (rejected)'}")


if __name__ == "__main__":
    main()
```

### Steps

**Step 1 — Run the Encrypt-then-MAC script**

```bash
python code/task9_encrypt_then_mac.py
```

### Screenshots

**Screenshot 1 — `task9_encrypt_then_mac.py` terminal output**

<!-- Insert screenshot: terminal showing Valid case PASS, Ciphertext tampered FAIL (rejected), Tag tampered FAIL (rejected) -->

*What to observe:* The valid case passes. Both tampering cases are immediately rejected — no
decryption occurs for either. This confirms INT-CTXT security: the scheme cannot be fooled
into decrypting any ciphertext the sender did not produce.

### Explanation

Encrypt-then-MAC achieves **INT-CTXT** (integrity of ciphertexts) because the MAC is computed
over the ciphertext itself. Any modification to the ciphertext or IV invalidates the tag, and
the tag is verified *before* the decryption function is called. This eliminates the padding
oracle surface entirely. It is the construction recommended by cryptographers (Bellare &
Namprempre, 2000) and used in modern protocols like TLS 1.3 and the NaCl/libsodium library.

---

## Task 10 — Comparison Table

### Overview

A summary of all five constructions evaluated in this lab, comparing their privacy and
integrity properties.

### Source Code

```python
"""
Task 10 – Comparison Table
"""

def main():
    header = f"{'Method':<22} {'Privacy':<10} {'Integrity':<12} {'Secure?':<8}"
    sep    = "-" * len(header)

    rows = [
        ("AES-CBC only",       "Yes", "No",       "No"),
        ("Redundancy",         "Yes", "Weak",     "No"),
        ("Encrypt-and-MAC",    "Yes", "Partial",  "No"),
        ("MAC-then-Encrypt",   "Yes", "Partial",  "No"),
        ("Encrypt-then-MAC",   "Yes", "Yes",      "Yes"),
    ]

    print("=== Task 10: Comparison Table ===\n")
    print(header)
    print(sep)
    for method, privacy, integrity, secure in rows:
        print(f"{method:<22} {privacy:<10} {integrity:<12} {secure:<8}")

if __name__ == "__main__":
    main()
```

### Steps

**Step 1 — Run the comparison script**

```bash
python code/task10_comparison.py
```

### Screenshots

**Screenshot 1 — `task10_comparison.py` terminal output**

<!-- Insert screenshot: terminal showing the formatted comparison table -->

### Results Table

| Method             | Privacy | Integrity | Secure? | Notes                                      |
|--------------------|---------|-----------|---------|--------------------------------------------|
| AES-CBC only       | Yes     | No        | No      | No authentication; tampering undetectable  |
| Redundancy         | Yes     | Weak      | No      | Fixed sentinel easily bypassed             |
| Encrypt-and-MAC    | Yes     | Partial   | No      | MAC over plaintext; leaks info             |
| MAC-then-Encrypt   | Yes     | Partial   | No      | Must decrypt before verifying; oracle risk |
| Encrypt-then-MAC   | Yes     | Yes       | **Yes** | Verifies before decrypt; INT-CTXT secure   |

---

## Task 11 — Reflection

### Overview

Conceptual questions about authenticated encryption, INT-CTXT, and the importance of
construction order.

### Source Code

```python
"""
Task 11 – Reflection
"""

QUESTIONS = {
    "Q1": "Why is confidentiality alone insufficient?",
    "Q2": "What does INT-CTXT mean?",
    "Q3": "Why does integrity matter for secure communication?",
    "Q4": "Why does the order of encryption and MAC matter?",
    "Q5": "What is the key takeaway from Encrypt-then-MAC?",
}

ANSWERS = {
    "Q1": "TODO – fill in your answer",
    "Q2": "TODO – fill in your answer",
    "Q3": "TODO – fill in your answer",
    "Q4": "TODO – fill in your answer",
    "Q5": "TODO – fill in your answer",
}

def main():
    print("=== Task 11: Reflection ===\n")
    for key, question in QUESTIONS.items():
        print(f"{key}: {question}")
        print(f"     {ANSWERS[key]}\n")

if __name__ == "__main__":
    main()
```

### Reflection Answers

**Q1: Why is confidentiality alone insufficient?**

<!-- TODO: answer here -->

**Q2: What does INT-CTXT mean?**

<!-- TODO: answer here -->

**Q3: Why does integrity matter for secure communication?**

<!-- TODO: answer here -->

**Q4: Why does the order of encryption and MAC matter?**

<!-- TODO: answer here -->

**Q5: What is the key takeaway from Encrypt-then-MAC?**

<!-- TODO: answer here -->

---

## References

- Bellare, M. & Namprempre, C. (2000). *Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm.* ASIACRYPT 2000.
- NIST FIPS 197 — Advanced Encryption Standard (AES)
- Python `cryptography` library documentation: https://cryptography.io

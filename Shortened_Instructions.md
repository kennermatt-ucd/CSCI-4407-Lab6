
# Authenticated Encryption Lab – Final Checklist Version

## Each Task MUST Include

* Python script
* Terminal screenshots (clear + readable)
* Outputs:

  * keys
  * IVs
  * ciphertexts
  * tags (if applicable)
* Explanation:

  * what was done
  * what happened
  * why it matters

---

## Task Requirements

### Task 1 – Setup

* Show:

  * directory creation
  * message files + contents
  * SHA256 hashes

---

### Task 2 – AES-CBC

* Show:

  * key, IV, ciphertext
  * correct decrypted plaintext
* Explain confidentiality

---

### Task 3 – No Integrity

* Modify ciphertext
* Show:

  * tampered ciphertext
  * decryption still produces output
* Explain lack of integrity

---

### Task 4 – Bit-Flipping

* Show:

  * original plaintext
  * modified decrypted plaintext
* Explain CBC malleability + risk

---

### Task 5 – Redundancy

* Show:

  * redundancy value
  * successful verification (untampered)
* Explain intended purpose

---

### Task 6 – Break Redundancy

* Perform **≥3 tampering attempts**
* Show:

  * results (pass/fail)
* Explain why redundancy is insecure

---

### Task 7 – Encrypt-and-MAC

* Show valid execution
* Explain:

  * what is authenticated
  * weakness of design

---

### Task 8 – MAC-then-Encrypt

* Show:

  * valid execution
  * tampering behavior
* Explain why composition order matters

---

### Task 9 – Encrypt-then-MAC (CRITICAL)

* MUST:

  * verify tag **before decryption**
* Show:

  * valid case
  * ciphertext tamper → rejected
  * tag tamper → rejected
* Explain why this is secure

---

### Task 10 – Comparison Table

Include all methods:

| Method | Privacy | Integrity | Secure? |

---

### Task 11 – Reflection

Answer clearly:

* why confidentiality alone is insufficient
* what INT-CTXT means
* why integrity matters
* why order matters
* key takeaway from Encrypt-then-MAC

---

## Final Submission Requirements

* Single PDF
* Organized by Task 1–11
* Code included (embedded or attached)
* Screenshots + outputs included
* Clear explanations (not just raw results)
* Results must be reproducible

---

# ✅ Bottom Line

If you follow this version, you will:

* ✔ hit every rubric category
* ✔ avoid common deductions
* ✔ cover all required evidence

---

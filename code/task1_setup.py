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

"""
Task 10 – Comparison Table
Print a summary table comparing all authenticated-encryption methods.
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

"""
DecodeLabs Industrial Training Kit
Project 2: Basic Encryption & Decryption
-------------------------------------------------
Implements the Caesar Cipher (mono-alphabetic shift cipher)
following the IPO Model: Plaintext -> (Algorithm + Key) -> Ciphertext

Formulas:
    Encryption:  E(x) = (x + n) % 26
    Decryption:  D(x) = (x - n) % 26

Bonus: A simple Vigenere cipher is also included, as suggested
in the project's conclusion for going beyond the basics.
"""


def caesar_encrypt(text, shift):
    """
    Encrypts text using a Caesar cipher with the given shift key.
    Preserves case, and leaves spaces/punctuation/digits unchanged
    (handles the 'edge cases' requirement from the project brief).
    """
    result = []
    for char in text:
        if char.isupper():
            # 'A' = 65 -> shift to base 0, apply shift, wrap with %26, shift back
            shifted = (ord(char) - ord('A') + shift) % 26 + ord('A')
            result.append(chr(shifted))
        elif char.islower():
            # 'a' = 97
            shifted = (ord(char) - ord('a') + shift) % 26 + ord('a')
            result.append(chr(shifted))
        else:
            # Non-alphabetic characters (spaces, numbers, punctuation) stay as-is
            result.append(char)
    return "".join(result)


def caesar_decrypt(text, shift):
    """
    Decrypts text encrypted with caesar_encrypt using the same shift key.
    Symmetric encryption: D(x) = (x - n) % 26, same key locks and unlocks.
    """
    # Decryption is just encryption with the negative shift
    return caesar_encrypt(text, -shift)


def vigenere_encrypt(text, key):
    """
    Bonus: Vigenere cipher - uses a keyword to generate a sequence
    of shifts, instead of a single fixed shift.
    """
    result = []
    key = key.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.isupper():
                shifted = (ord(char) - ord('A') + shift) % 26 + ord('A')
            else:
                shifted = (ord(char) - ord('a') + shift) % 26 + ord('a')
            result.append(chr(shifted))
            key_index += 1  # only advance the key on letters
        else:
            result.append(char)
    return "".join(result)


def vigenere_decrypt(text, key):
    """
    Decrypts text encrypted with vigenere_encrypt using the same keyword.
    """
    result = []
    key = key.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.isupper():
                shifted = (ord(char) - ord('A') - shift) % 26 + ord('A')
            else:
                shifted = (ord(char) - ord('a') - shift) % 26 + ord('a')
            result.append(chr(shifted))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def main():
    print("=" * 50)
    print(" DecodeLabs - Project 2: Encryption & Decryption")
    print("=" * 50)

    print("\nChoose a cipher:")
    print("1. Caesar Cipher (numeric shift key)")
    print("2. Vigenere Cipher (word/phrase key)")
    choice = input("Enter choice (1 or 2): ").strip()

    text = input("\nEnter text to encrypt: ")

    if choice == "1":
        shift = int(input("Enter shift key (e.g. 3): ").strip())

        encrypted = caesar_encrypt(text, shift)
        decrypted = caesar_decrypt(encrypted, shift)

        print("\n--- RESULTS ---")
        print(f"Original Text : {text}")
        print(f"Shift Key     : {shift}")
        print(f"Encrypted     : {encrypted}")
        print(f"Decrypted     : {decrypted}")

    elif choice == "2":
        key = input("Enter keyword (letters only, e.g. KEY): ").strip()

        encrypted = vigenere_encrypt(text, key)
        decrypted = vigenere_decrypt(encrypted, key)

        print("\n--- RESULTS ---")
        print(f"Original Text : {text}")
        print(f"Key Word      : {key}")
        print(f"Encrypted     : {encrypted}")
        print(f"Decrypted     : {decrypted}")

    else:
        print("Invalid choice. Please run again and enter 1 or 2.")


if __name__ == "__main__":
    main()

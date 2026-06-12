
# METHOD 1: CAESAR CIPHER
# Shifts every letter by a fixed number (the "key").
# Non-letters (spaces, punctuation) are left unchanged.


def caesar_encrypt(text, shift):
    """
    Encrypt text using Caesar cipher.
    Each letter is shifted forward by 'shift' positions in the alphabet.
    Example: 'A' with shift 3 → 'D'
    """
    result = ""  # will hold the encrypted output

    for char in text:
        if char.isupper():
            # ord() gives the ASCII number of a character.
            # Subtract 65 (='A') to get 0-based alphabet index.
            # Add shift, use % 26 to wrap around (Z → A).
            # Add 65 back to get the ASCII number, then chr() converts back to a letter.
            shifted = (ord(char) - 65 + shift) % 26 + 65
            result += chr(shifted)

        elif char.islower():
            # Same logic, but lowercase starts at ASCII 97 (='a')
            shifted = (ord(char) - 97 + shift) % 26 + 97
            result += chr(shifted)

        else:
            # Not a letter — keep it exactly as-is (space, !, ?, 3, etc.)
            result += char

    return result


def caesar_decrypt(text, shift):
    """
    Decrypt a Caesar-encrypted text.
    Decryption is just encryption with the opposite shift.
    Shift forward by (26 - shift) = same as shifting backward.
    """
    return caesar_encrypt(text, 26 - (shift % 26))


# METHOD 2: ROT-13
# A special case of Caesar cipher with a fixed shift of 13.
# Because 13 + 13 = 26 (full alphabet), encrypt = decrypt.
# Calling it twice always restores the original — no key needed.

def rot13(text):
    """
    Apply ROT-13 to text. Works as both encrypt and decrypt.
    """
    return caesar_encrypt(text, 13)


# METHOD 3: VIGENÈRE CIPHER
# Uses a keyword instead of a single shift number.
# Each letter in the message gets a DIFFERENT shift,
# determined by the corresponding letter in the keyword.
# Much harder to crack than Caesar cipher.


def vigenere_encrypt(text, key):
    """
    Encrypt text using the Vigenère cipher.
    The key repeats to match the length of the message.
    Example: key="KEY", message="HELLO"
      H + K(10) = R
      E + E(4)  = I
      L + Y(24) = J
      L + K(10) = V  (key wraps back to start)
      O + E(4)  = S
    → Encrypted: RIJVS
    """
    # Clean the key: keep only letters, convert to uppercase
    key = key.upper()
    key = ''.join(ch for ch in key if ch.isalpha())

    if not key:
        print("[!] Vigenère key must contain at least one letter.")
        return None

    result = ""
    key_index = 0  # tracks our position in the repeating key

    for char in text:
        if char.isalpha():
            # Get shift value from current key letter (A=0, B=1, ... Z=25)
            shift = ord(key[key_index % len(key)]) - ord('A')
            key_index += 1  # advance key position only for letters

            if char.isupper():
                encrypted_char = chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                encrypted_char = chr((ord(char) - 97 + shift) % 26 + 97)

            result += encrypted_char
        else:
            result += char  # preserve spaces, punctuation

    return result


def vigenere_decrypt(text, key):
    """
    Decrypt a Vigenère-encrypted text.
    Instead of adding the shift, we subtract it (and add 26 to avoid negatives).
    """
    key = key.upper()
    key = ''.join(ch for ch in key if ch.isalpha())

    if not key:
        return None

    result = ""
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            key_index += 1

            if char.isupper():
                decrypted_char = chr((ord(char) - 65 - shift + 26) % 26 + 65)
            else:
                decrypted_char = chr((ord(char) - 97 - shift + 26) % 26 + 97)

            result += decrypted_char
        else:
            result += char

    return result



# INPUT VALIDATION
# Makes sure the user doesn't enter empty input or bad values


def get_valid_text(prompt):
    """Ask for text input, reject empty strings."""
    while True:
        text = input(prompt)
        if text.strip():
            return text
        print("[!] Input cannot be empty. Please try again.\n")


def get_valid_shift():
    """Ask for a shift value between 1 and 25."""
    while True:
        try:
            shift = int(input("Enter shift key (1–25): "))
            if 1 <= shift <= 25:
                return shift
            else:
                print("[!] Shift must be between 1 and 25.\n")
        except ValueError:
            print("[!] Please enter a whole number.\n")


def get_valid_key():
    """Ask for a Vigenère keyword (letters only)."""
    while True:
        key = input("Enter keyword (letters only, e.g. KEY): ").strip()
        if key.isalpha():
            return key
        print("[!] Keyword must contain only letters, no spaces or numbers.\n")



# DISPLAY HELPER
# Neatly prints original, encrypted, and decrypted text

def display_results(original, encrypted, decrypted):
    print()
    print("=" * 45)
    print(f"  Original Text  : {original}")
    print(f"  Encrypted Text : {encrypted}")
    print(f"  Decrypted Text : {decrypted}")
    print("=" * 45)

    # Verify that decryption restored the original exactly
    if original == decrypted:
        print("  [✓] Decryption successful — message restored!")
    else:
        print("  [✗] Decryption mismatch — something went wrong.")
    print()



# MAIN PROGRAM

def main():
    print("=" * 45)
    print("   Basic Encryption & Decryption Tool")
    print("=" * 45)

    # Step 1: Choose encryption method
    print("\nSelect encryption method:")
    print("  1. Caesar Cipher")
    print("  2. ROT-13")
    print("  3. Vigenère Cipher (advanced)")

    while True:
        choice = input("\nEnter choice (1/2/3): ").strip()
        if choice in ("1", "2", "3"):
            break
        print("[!] Please enter 1, 2, or 3.")

    # Step 2: Get the message
    message = get_valid_text("\nEnter your message: ")

    # Step 3: Encrypt and decrypt based on chosen method
    if choice == "1":
        shift = get_valid_shift()
        encrypted  = caesar_encrypt(message, shift)
        decrypted  = caesar_decrypt(encrypted, shift)
        print(f"\n--- Caesar Cipher (shift = {shift}) ---")
        display_results(message, encrypted, decrypted)

    elif choice == "2":
        encrypted = rot13(message)
        decrypted = rot13(encrypted)   # applying ROT-13 twice restores the original
        print("\n--- ROT-13 ---")
        display_results(message, encrypted, decrypted)

    elif choice == "3":
        key = get_valid_key()
        encrypted = vigenere_encrypt(message, key)
        if encrypted:
            decrypted = vigenere_decrypt(encrypted, key)
            print(f"\n--- Vigenère Cipher (keyword = {key.upper()}) ---")
            display_results(message, encrypted, decrypted)


# Standard Python entry point
if __name__ == "__main__":
    main()
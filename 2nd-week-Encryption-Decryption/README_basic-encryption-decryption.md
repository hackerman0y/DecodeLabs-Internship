# Basic Encryption & Decryption

![Python](https://img.shields.io/badge/Python-3.x-blue) ![Security](https://img.shields.io/badge/Topic-Cybersecurity-red) ![Level](https://img.shields.io/badge/Level-Beginner-green)

## Description

A command-line tool that demonstrates fundamental encryption and decryption concepts used in cybersecurity. The program accepts a text message, encrypts it using a chosen cipher, then decrypts it back to prove the process is fully reversible.

Supports three encryption methods including the classic **Caesar Cipher**, **ROT-13**, and the more advanced **Vigenère Cipher**.

## Features

- **Caesar Cipher** — shift letters by a custom key (1–25)
- **ROT-13** — fixed shift of 13; applying it twice restores the original
- **Vigenère Cipher** — keyword-based encryption, harder to crack
- Preserves spaces, punctuation, and special characters
- Verifies that decryption perfectly restores the original message
- Input validation for all user entries

## How to Run

### Prerequisites
- Python 3.x installed → [Download here](https://www.python.org/downloads/)

### Steps

```bash
# 1. Navigate to the project folder
cd basic-encryption-decryption

# 2. Run the program
python Basic-Encryption-and-Decryption.py
```

### Example

```
Select encryption method:
  1. Caesar Cipher
  2. ROT-13
  3. Vigenère Cipher (advanced)

Enter choice (1/2/3): 1
Enter your message: Hello World
Enter shift key (1–25): 3

--- Caesar Cipher (shift = 3) ---
  Original Text  : Hello World
  Encrypted Text : Khoor Zruog
  Decrypted Text : Hello World
  [✓] Decryption successful — message restored!
```

## Concepts Demonstrated

- Character-level string manipulation
- `ord()` and `chr()` for ASCII arithmetic
- Modular arithmetic (`% 26`) for alphabet wrapping
- Functions, loops, and input validation

## Project Structure

```
basic-encryption-decryption/
│
├── Basic-Encryption-and-Decryption.py   # Main program
└── README.md                            # Project documentation
```

---

> **Cyber Security Project 2** — Built as part of a cybersecurity fundamentals series.

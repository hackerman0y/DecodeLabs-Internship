# Password Strength Checker

![Python](https://img.shields.io/badge/Python-3.x-blue) ![Security](https://img.shields.io/badge/Topic-Cybersecurity-red) ![Level](https://img.shields.io/badge/Level-Beginner-green)

## Description

A command-line tool that analyzes a user's password and determines whether it is **Weak**, **Medium**, or **Strong** based on cybersecurity best practices.

The tool checks multiple security criteria, assigns a score out of 100, detects common/weak passwords, and provides actionable suggestions to improve password strength.

## Features

- Evaluates password length, character variety, and complexity
- Detects common weak passwords (e.g. `123456`, `password`, `admin`)
- Assigns a security score from **0 to 100**
- Displays a checklist of passed and failed criteria
- Suggests specific improvements to strengthen the password

## How to Run

### Prerequisites
- Python 3.x installed → [Download here](https://www.python.org/downloads/)

### Steps

```bash
# 1. Navigate to the project folder
cd password-strength-checker

# 2. Run the program
python password_checker.py
```

### Example

```
Enter your password: Hello123

Password Strength: Medium
Security Score   : 45 / 100

Reason:
  ✓ Password is at least 8 characters
  ✓ Contains uppercase letters
  ✓ Contains lowercase letters
  ✓ Contains numbers
  ✗ Password is at least 12 characters
  ✗ Contains special characters

Suggestions to improve:
  → Aim for 12+ characters for stronger security
  → Use special characters like ! @ # $ % ^ &
```

## Concepts Demonstrated

- String manipulation and iteration
- Regular expressions (`re` module)
- Functions and modular code design
- Conditional logic and input validation

## Project Structure

```
password-strength-checker/
│
├── password_checker.py   # Main program
└── README.md             # Project documentation
```

---

> **Cyber Security Project 1** — Built as part of a cybersecurity fundamentals series.

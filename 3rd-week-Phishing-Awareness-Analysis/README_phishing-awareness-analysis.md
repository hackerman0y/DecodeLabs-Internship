# Phishing Awareness Analysis

![Python](https://img.shields.io/badge/Python-3.x-blue) ![Security](https://img.shields.io/badge/Topic-Cybersecurity-red) ![Level](https://img.shields.io/badge/Level-Beginner-green)

## Description

A command-line analysis tool that examines emails or messages and determines whether they contain **phishing indicators**. The tool scans for suspicious patterns, assigns a risk score, lists all red flags detected, and explains why each one is dangerous.

Designed to build awareness of social engineering tactics used in real-world phishing attacks.

## Features

- Detects **8 categories** of phishing indicators:
  - Urgent language (`act now`, `immediately`, `deadline`)
  - Sensitive information requests (`password`, `credit card`, `SSN`)
  - Suspicious URLs (unusual domains, IP-based links)
  - Shortened URLs (`bit.ly`, `tinyurl`, etc.)
  - Threats and negative consequences (`suspended`, `terminated`)
  - Fake rewards and prizes (`winner`, `claim your`, `lottery`)
  - Impersonation of authority (`your bank`, `IT department`)
  - Excessive capital letters (`URGENT`, `WARNING`)
- Assigns a **risk score from 0 to 100**
- Highlights suspicious keywords found in the message
- Supports **multiple message analysis** in one session
- Generates a **JSON report file** (bonus feature)

## How to Run

### Prerequisites
- Python 3.x installed → [Download here](https://www.python.org/downloads/)

### Steps

```bash
# 1. Navigate to the project folder
cd phishing-awareness-analysis

# 2. Run the program
python phishing_analysis.py
```

### Example

```
Paste the email or message to analyze:
Your bank account has been suspended. Click here immediately
to verify your password: http://secure-bank-login.xyz/verify

Result     : HIGH RISK — LIKELY PHISHING
Risk Score : 85 / 100

Red Flags Detected (4):

  1. [Urgent language]
     ✗ Uses urgency to pressure you into acting without thinking.

  2. [Sensitive information request]
     ✗ Requests passwords — no legitimate service asks for this via email.

  3. [Suspicious URL]
     ✗ Contains a suspicious domain with an unusual extension.

  4. [Threat or negative consequence]
     ✗ Threatens account suspension to create fear and panic.

Suspicious keywords found: immediately, password, suspended, verify
```

## Concepts Demonstrated

- Regular expressions (`re` module) for pattern matching
- Rule-based detection systems
- Dictionary data structures for rule definitions
- File I/O for JSON report generation
- Loops, functions, and modular design

## Project Structure

```
phishing-awareness-analysis/
│
├── phishing_analysis.py   # Main program
└── README.md              # Project documentation
```

---

> **Cyber Security Project 3** — Built as part of a cybersecurity fundamentals series.

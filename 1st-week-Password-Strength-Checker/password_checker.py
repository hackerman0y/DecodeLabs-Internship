

import re  # built-in module for pattern matching

# 1. CONSTANT: list of common/weak passwords to detect 

COMMON_PASSWORDS = [
    "123456", "password", "admin", "qwerty",
    "letmein", "111111", "123123", "abc123",
    "iloveyou", "welcome", "monkey", "dragon"
]



# 2. FUNCTION: check individual password rules
# Each function takes the password string and returns True/False


def has_uppercase(password):
    """Returns True if password contains at least one uppercase letter."""
    return bool(re.search(r'[A-Z]', password))


def has_lowercase(password):
    """Returns True if password contains at least one lowercase letter."""
    return bool(re.search(r'[a-z]', password))


def has_digit(password):
    """Returns True if password contains at least one digit (0–9)."""
    return bool(re.search(r'[0-9]', password))


def has_special_char(password):
    """Returns True if password contains at least one special character."""
    # [^A-Za-z0-9] means 'anything that is NOT a letter or digit'
    return bool(re.search(r'[^A-Za-z0-9]', password))


def is_common_password(password):
    """Returns True if the password matches a known weak/common password."""
    return password.lower() in COMMON_PASSWORDS



# 3. FUNCTION: calculate a security score (0 to 100)
# Points are awarded for each condition the password meets


def calculate_score(password):
    score = 0

    if len(password) >= 8:   score += 15   # minimum length
    if len(password) >= 12:  score += 15   # good length
    if len(password) >= 16:  score += 10   # great length
    if has_uppercase(password): score += 15
    if has_lowercase(password): score += 15
    if has_digit(password):     score += 15
    if has_special_char(password): score += 15

    # Common passwords are capped at a very low score
    if is_common_password(password):
        score = min(score, 20)

    return score  # max possible: 100



# 4. FUNCTION: determine strength rating based on score
#Returns one of: "Weak", "Medium", or "Strong"


def get_strength(password):
    if is_common_password(password):
        return "Weak"           # override: always weak if common

    score = calculate_score(password)

    if score < 35:
        return "Weak"
    elif score < 70:
        return "Medium"
    else:
        return "Strong"



# 5. FUNCTION: build the reason/checklist message
# Loops through each condition and marks ✓ or ✗

def build_reason(password):
    checks = []

    # Each tuple: (condition result, message)
    checks.append((len(password) >= 8,        "Password is at least 8 characters"))
    checks.append((len(password) >= 12,       "Password is at least 12 characters"))
    checks.append((has_uppercase(password),   "Contains uppercase letters"))
    checks.append((has_lowercase(password),   "Contains lowercase letters"))
    checks.append((has_digit(password),       "Contains numbers"))
    checks.append((has_special_char(password),"Contains special characters"))

    lines = []
    for passed, message in checks:
        symbol = "✓" if passed else "✗"
        lines.append(f"  {symbol} {message}")

    # Bonus: warn if it's a known common password
    if is_common_password(password):
        lines.append("  ✗ This is a very common password — avoid it!")

    return "\n".join(lines)



# 6. FUNCTION: suggest improvements
# Only suggests what's missing from the password


def get_suggestions(password):
    tips = []

    if len(password) < 8:
        tips.append("→ Make it at least 8 characters long")
    if len(password) < 12:
        tips.append("→ Aim for 12+ characters for stronger security")
    if not has_uppercase(password):
        tips.append("→ Add uppercase letters (e.g. A, B, C)")
    if not has_lowercase(password):
        tips.append("→ Add lowercase letters (e.g. a, b, c)")
    if not has_digit(password):
        tips.append("→ Mix in some numbers (e.g. 3, 7, 9)")
    if not has_special_char(password):
        tips.append("→ Use special characters like ! @ # $ % ^ &")
    if is_common_password(password):
        tips.append("→ Avoid dictionary words and common patterns")

    return tips



# 7. MAIN PROGRAM


def main():
    print("=" * 45)
    print("       Password Strength Checker")
    print("=" * 45)

    # Step 1: Accept input from user
    password = input("\nEnter your password: ")

    # Step 2: Handle empty input
    if len(password) == 0:
        print("\n[!] No password entered. Exiting.")
        return

    # Step 3: Evaluate strength
    strength = get_strength(password)
    score    = calculate_score(password)
    reason   = build_reason(password)
    tips     = get_suggestions(password)

    # Step 4: Display results
    print(f"\nPassword Strength: {strength}")
    print(f"Security Score   : {score} / 100\n")

    print("Reason:")
    print(reason)

    # Step 5: Display improvement tips (bonus)
    if tips:
        print("\nSuggestions to improve:")
        for tip in tips:
            print(f"  {tip}")
    else:
        print("\n✓ No suggestions — this is a strong password!")

    print("\n" + "=" * 45)


# Standard Python entry point
if __name__ == "__main__":
    main()
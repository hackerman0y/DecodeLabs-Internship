# ============================================================
#  Phishing Awareness Analysis — Cyber Security Project 3
#  Concepts: functions, loops, string handling, conditionals
# ============================================================

import re      # pattern matching for detecting phishing keywords
import json    # for generating a report file (bonus)
from datetime import datetime  # for timestamping reports


# ============================================================
# 1. PHISHING RULE DEFINITIONS
#    Each rule is a dictionary with:
#      - name       : display name of the indicator
#      - patterns   : list of keyword/phrase patterns to search for
#      - explanation: why this indicator is dangerous
#      - severity   : how much it adds to the risk score (0–100 total)
# ============================================================

PHISHING_RULES = [
    {
        "id": "urgent",
        "name": "Urgent language",
        "patterns": [
            r"\burgent\b", r"\bimmediately\b", r"\bact now\b",
            r"\bwithin \d+ hours?\b", r"\bdon'?t miss\b",
            r"\blast chance\b", r"\blimited time\b",
            r"\bexpired?\b", r"\bdeadline\b", r"\basap\b"
        ],
        "explanation": (
            "This message uses urgency to pressure you into acting "
            "without thinking. Legitimate organizations rarely demand "
            "immediate action via email."
        ),
        "severity": 20
    },
    {
        "id": "sensitive",
        "name": "Sensitive information request",
        "patterns": [
            r"\bpassword\b", r"\bcredential[s]?\b",
            r"\bcredit card\b", r"\bsocial security\b", r"\bssn\b",
            r"\bbank account\b", r"\bpin number\b",
            r"\bdate of birth\b", r"\bpersonal details?\b",
            r"\bverify your\b", r"\bconfirm your\b"
        ],
        "explanation": (
            "Requests for passwords or personal/financial data are a "
            "major red flag. No legitimate bank or service will ask for "
            "your password via email."
        ),
        "severity": 25
    },
    {
        "id": "suspicious_url",
        "name": "Suspicious URL",
        "patterns": [
            r"https?://[^\s]*(secure[_\-]?\w+\.xyz)",
            r"https?://[^\s]*(login[_\-]?\w+\.\w{2,})",
            r"https?://[^\s]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            r"https?://[^\s]*\.(xyz|tk|ml|ga|cf|gq)[/\s]"
        ],
        "explanation": (
            "The message contains a URL with a suspicious or unusual "
            "domain. Phishers often mimic real websites with slight "
            "spelling differences or uncommon extensions."
        ),
        "severity": 25
    },
    {
        "id": "shortened_url",
        "name": "Shortened URL (bonus)",
        "patterns": [
            r"https?://(bit\.ly|tinyurl\.com|goo\.gl|t\.co|"
            r"ow\.ly|rb\.gy|is\.gd|buff\.ly|cutt\.ly)/\S+"
        ],
        "explanation": (
            "URL shorteners hide the real destination. Attackers use "
            "them so you cannot tell where a link leads before clicking."
        ),
        "severity": 15
    },
    {
        "id": "threat",
        "name": "Threat or negative consequence",
        "patterns": [
            r"\bsuspend(ed)?\b", r"\bterminate[sd]?\b",
            r"\bclosed?\b", r"\blocked\b", r"\bblocked?\b",
            r"\bdisabled?\b", r"\bpenalty\b", r"\blegal action\b",
            r"\blawsuit\b", r"\bpermanently\b"
        ],
        "explanation": (
            "Threatening account closure or legal action is designed to "
            "create fear and panic, pushing you to comply without question."
        ),
        "severity": 15
    },
    {
        "id": "reward",
        "name": "Fake reward or prize",
        "patterns": [
            r"\bwinner\b", r"\byou (have )?won\b",
            r"\bcongratulations\b", r"\bfree prize\b",
            r"\bclaim your\b", r"\byou('ve| have) been selected\b",
            r"\blottery\b", r"\blucky\b", r"\bgift card\b",
            r"\$\d+"
        ],
        "explanation": (
            "Promises of prizes or money are lures to get you to provide "
            "personal information or click malicious links."
        ),
        "severity": 15
    },
    {
        "id": "impersonation",
        "name": "Impersonation of authority",
        "patterns": [
            r"\byour bank\b", r"\bit department\b",
            r"\bhelpdesk\b", r"\bsupport team\b",
            r"\bpaypal\b", r"\bmicrosoft\b", r"\bapple\b",
            r"\bamazon\b", r"\bgovernment\b", r"\birs\b",
            r"\btax authority\b"
        ],
        "explanation": (
            "The message pretends to be from a trusted organization "
            "to gain your trust. Always verify through official channels."
        ),
        "severity": 15
    },
    {
        "id": "allcaps",
        "name": "Excessive capital letters",
        "patterns": [
            r"\b[A-Z]{4,}\b"    # four or more consecutive capital letters
        ],
        "explanation": (
            "ALL CAPS words like URGENT or WARNING are a manipulation "
            "tactic to provoke panic and bypass rational thinking."
        ),
        "severity": 5
    }
]


# ============================================================
# 2. CORE ANALYSIS FUNCTION
#    Scans the message against every rule.
#    Returns a list of triggered rules and the total risk score.
# ============================================================

def analyze_message(message):
    """
    Analyze a message for phishing indicators.
    Returns: (triggered_rules, risk_score, highlighted_keywords)
    """
    triggered = []          # rules that matched
    found_keywords = []     # all matching keyword strings
    total_score = 0

    for rule in PHISHING_RULES:
        rule_matched = False

        for pattern in rule["patterns"]:
            # re.IGNORECASE makes matching case-insensitive
            matches = re.findall(pattern, message, re.IGNORECASE)
            if matches:
                rule_matched = True
                found_keywords.extend(matches)

        if rule_matched:
            triggered.append(rule)
            total_score += rule["severity"]

    # Cap the score at 100
    total_score = min(total_score, 100)

    return triggered, total_score, found_keywords


# ============================================================
# 3. VERDICT FUNCTION
#    Converts a numeric risk score into a human-readable verdict
# ============================================================

def get_verdict(score):
    """Return verdict label based on risk score."""
    if score == 0:
        return "SAFE"
    elif score < 40:
        return "LOW SUSPICION"
    elif score < 70:
        return "SUSPICIOUS"
    else:
        return "HIGH RISK — LIKELY PHISHING"


# ============================================================
# 4. DISPLAY FUNCTION
#    Prints the analysis results in a structured format
# ============================================================

def display_results(message, triggered, score, keywords):
    """Print a clean phishing analysis report to the terminal."""
    verdict = get_verdict(score)

    print()
    print("=" * 55)
    print("         PHISHING AWARENESS ANALYSIS REPORT")
    print("=" * 55)
    print(f"\n  Message analyzed:\n  \"{message[:80]}{'...' if len(message) > 80 else ''}\"\n")
    print(f"  Result     : {verdict}")
    print(f"  Risk Score : {score} / 100")
    print("-" * 55)

    if not triggered:
        print("\n  [✓] No phishing indicators detected.")
        print("  This message appears safe based on known patterns.")
    else:
        print(f"\n  Red Flags Detected ({len(triggered)}):\n")
        for i, rule in enumerate(triggered, 1):
            print(f"  {i}. [{rule['name']}]")
            print(f"     ✗ {rule['explanation']}")
            print()

    # Highlight detected keywords (bonus)
    if keywords:
        unique_kw = list(set(kw.strip() for kw in keywords if kw.strip()))
        print("-" * 55)
        print(f"  Suspicious keywords found: {', '.join(unique_kw[:10])}")

    print("=" * 55)
    print()


# ============================================================
# 5. REPORT GENERATOR (bonus)
#    Saves the analysis to a JSON file for documentation
# ============================================================

def generate_report(message, triggered, score):
    """
    Save the analysis as a JSON report file.
    File is named with timestamp so each report is unique.
    """
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message_preview": message[:100],
        "verdict": get_verdict(score),
        "risk_score": score,
        "flags_triggered": len(triggered),
        "red_flags": [
            {"name": r["name"], "explanation": r["explanation"]}
            for r in triggered
        ]
    }

    filename = f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"  [✓] Report saved to: {filename}\n")
    return filename


# ============================================================
# 6. INPUT VALIDATION
#    Rejects empty input and handles the multi-message loop
# ============================================================

def get_message():
    """Prompt user for a non-empty message."""
    while True:
        print("Paste the email or message to analyze.")
        print("(You can type multiple lines. Enter a blank line when done.)\n")

        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)

        message = " ".join(lines).strip()

        if message:
            return message
        print("\n[!] No message entered. Please try again.\n")


# ============================================================
# 7. MAIN PROGRAM
#    Ties everything together and supports multiple messages
# ============================================================

def main():
    print("=" * 55)
    print("      Phishing Awareness Analysis Tool")
    print("      Cyber Security Project 3")
    print("=" * 55)

    while True:
        print()
        message = get_message()

        # Run the analysis
        triggered, score, keywords = analyze_message(message)

        # Show results
        display_results(message, triggered, score, keywords)

        # Ask if user wants to save a report (bonus)
        save = input("  Save a report file? (y/n): ").strip().lower()
        if save == 'y':
            generate_report(message, triggered, score)

        # Offer to analyze another message (bonus — multi-message)
        again = input("  Analyze another message? (y/n): ").strip().lower()
        if again != 'y':
            print("\n  Stay safe online. Always verify before you click.\n")
            break


if __name__ == "__main__":
    main()
import re
import hmac

def check_password_strength(password: str) -> dict:
    """
    Evaluates password strength based on:
    - Length (< 8 = immediate fail)
    - Uppercase letters [A-Z]
    - Digits [0-9]
    - Special symbols
    
    Returns: dict with strength, score, and feedback
    """
    
    feedback = []
    score = 0
    
    # --- RULE 1: Length check (zero point / gatekeeper) ---
    if len(password) < 8:
        return {
            "strength": "WEAK",
            "score": 0,
            "feedback": ["Password must be at least 8 characters. Immediate fail."]
        }
    elif len(password) >= 12:
        score += 2
    else:
        score += 1

    # --- RULE 2: Pythonic pattern checks (any() = short-circuit, O(n)) ---
    has_upper   = any(c.isupper() for c in password)
    has_digit   = any(c.isdigit() for c in password)
    has_symbol  = any(not c.isalnum() for c in password)
    has_lower   = any(c.islower() for c in password)

    if has_upper:
        score += 1
    else:
        feedback.append("Add uppercase letters [A-Z].")

    if has_digit:
        score += 1
    else:
        feedback.append("Add numbers [0-9].")

    if has_symbol:
        score += 1
    else:
        feedback.append("Add symbols (e.g. @, #, !, $).")

    if has_lower:
        score += 1

    # --- RULE 3: Bonus — common leaked password check ---
    COMMON_PASSWORDS = {
        "password", "password123", "123456", "12345678",
        "qwerty", "abc123", "letmein", "welcome", "monkey"
    }
    # Use hmac.compare_digest → constant-time comparison (prevents timing attacks)
    is_common = any(
        hmac.compare_digest(password.lower(), common)
        for common in COMMON_PASSWORDS
    )
    if is_common:
        return {
            "strength": "WEAK",
            "score": 0,
            "feedback": ["Password found in common/leaked password list. Change it immediately."]
        }

    # --- Classify strength ---
    if score >= 6:
        strength = "STRONG"
    elif score >= 4:
        strength = "MEDIUM"
    else:
        strength = "WEAK"

    if not feedback:
        feedback.append("All checks passed.")

    return {
        "strength": strength,
        "score": score,
        "feedback": feedback
    }


def main():
    print("=" * 45)
    print("  DecodeLabs | Password Strength Checker")
    print("=" * 45)

    while True:
        password = input("\nEnter password to check (or 'quit'): ")
        if password.lower() == "quit":
            break

        result = check_password_strength(password)

        print(f"\n  Strength : {result['strength']}")
        print(f"  Score    : {result['score']}/7")
        print("  Feedback :")
        for tip in result["feedback"]:
            print(f"    → {tip}")

    print("\nGatekeeper session closed.")


if __name__ == "__main__":
    main()
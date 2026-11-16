"""
Password Strength Checker
PS No. 10

Problem Statement:
Build a program that checks a password against security rules and
classifies it as Weak, Medium or Strong, giving suggestions to improve it.

Language: Python 3
Concepts: Strings, Sets, Conditions, Regex

Scoring: One point per rule -
    1. length >= 8
    2. has an uppercase letter
    3. has a lowercase letter
    4. has a digit
    5. has a special character from the set: @ # $ % & * !

Score 0-2 -> Weak
Score 3-4 -> Medium
Score 5   -> Strong

Extra: a 0-10 Complexity Score is also shown. It is based on
password entropy (bits of randomness), which depends on BOTH the
password's length and how many different character types it mixes
in - a true measure of how hard it would be to brute-force, not
just whether the 5 rubric rules were met.
"""

import re
import math

# The set of allowed special characters (using a set as required by the spec)
SPECIAL_CHARS = {'@', '#', '$', '%', '&', '*', '!'}


def check_rules(password):
    """
    Checks the password against each of the 5 rules.
    Returns a dictionary: {rule_name: True/False}
    """
    rules = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "digit": bool(re.search(r'\d', password)),
        "special": any(char in SPECIAL_CHARS for char in password),
    }
    return rules


def calculate_score(rules):
    """Score = number of rules passed (0 to 5)."""
    return sum(rules.values())


def classify_strength(score):
    """Classify based on score."""
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"


def calculate_complexity_score(password):
    """
    Complexity score (0-10) based on password ENTROPY, i.e. how many
    possible passwords an attacker would have to try.

    Step 1: figure out the "pool size" - how many distinct characters
    could appear at each position, based on which character types are
    actually used (lowercase, uppercase, digits, our special set, or
    any other symbol like a space/unicode character/punctuation).

    Step 2: entropy (in bits) = length x log2(pool_size)
    This grows with BOTH length and character variety, which is what
    makes a password genuinely harder to guess - not just "has 8+
    characters" or "has one digit".

    Step 3: map entropy bits onto a 0-10 scale. ~80 bits is considered
    very strong by security standards, so we scale so that 80 bits
    lands at 10 and cap there.
    """
    if len(password) == 0:
        return 0

    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in SPECIAL_CHARS for c in password):
        pool_size += len(SPECIAL_CHARS)

    # Any character outside a-z, A-Z, 0-9 and our special set
    # (other punctuation, unicode, etc.) widens the pool further.
    known_chars = set('abcdefghijklmnopqrstuvwxyz'
                       'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                       '0123456789') | SPECIAL_CHARS
    if any(c not in known_chars for c in password):
        pool_size += 32

    if pool_size == 0:
        return 0

    entropy_bits = len(password) * math.log2(pool_size)
    score = round(min(10, (entropy_bits / 80) * 10))
    return score


def get_suggestions(rules):
    """Build suggestion messages for each failed rule."""
    suggestion_map = {
        "length": "use at least 8 characters",
        "uppercase": "add an uppercase letter",
        "lowercase": "add a lowercase letter",
        "digit": "add a digit",
        "special": "add a special character (@#$%&*!)",
    }
    suggestions = [msg for rule, msg in suggestion_map.items() if not rules[rule]]
    return suggestions


def validate_input(password):
    """
    Validates the raw input before checking strength.
    Returns (is_valid, error_message)
    """
    if password == "":
        return False, "Password cannot be empty."
    if ' ' in password:
        return False, "Password must not contain spaces."
    return True, ""


def check_password_strength(password):
    """
    Main logic: validates, scores, classifies and builds the result message.
    Returns a formatted result string (also used by the test cases below).
    """
    is_valid, error = validate_input(password)
    if not is_valid:
        return error

    rules = check_rules(password)
    score = calculate_score(rules)
    strength = classify_strength(score)
    complexity = calculate_complexity_score(password)
    suggestions = get_suggestions(rules)

    result = f"Strength: {strength} ({score}/5)"
    result += f"\nComplexity Score: {complexity}/10"
    if suggestions:
        if len(suggestions) == 1:
            result += f"\nSuggestion: {suggestions[0]}"
        else:
            result += "\nSuggestions: " + ", ".join(suggestions)
    else:
        result += "\nNo suggestions. Your password is secure."

    return result


def run_test_cases():
    """Runs the 4 test cases given in the project spec."""
    print("=" * 50)
    print("RUNNING TEST CASES")
    print("=" * 50)

    test_cases = [
        ("Test Case 1: Normal Input", "abc123"),
        ("Test Case 2: Boundary / Minimum Input", "Hello123"),
        ("Test Case 3a: Invalid Input (empty)", ""),
        ("Test Case 3b: Invalid Input (space)", "Hello 123"),
        ("Test Case 4: Different Valid Scenario", "Hello@123Xy"),
    ]

    for label, pwd in test_cases:
        print(f"\n{label}")
        print(f"Password: {pwd!r}")
        print(check_password_strength(pwd))

    print("\n" + "=" * 50)


def main():
    """Interactive console entry point."""
    print("=" * 50)
    print("       PASSWORD STRENGTH CHECKER")
    print("=" * 50)
    print("Rules (1 point each): length>=8, uppercase, lowercase,")
    print("digit, special character (@#$%&*!)")
    print("-" * 50)

    while True:
        password = input("\nEnter a password to check (or 'q' to quit, 't' to run test cases): ")

        if password.lower() == 'q':
            print("Goodbye!")
            break
        elif password.lower() == 't':
            run_test_cases()
            continue

        print(check_password_strength(password))


if __name__ == "__main__":
    main()

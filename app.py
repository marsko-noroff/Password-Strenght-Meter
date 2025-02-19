from fastapi import FastAPI
from pydantic import BaseModel
import re
import string
from collections import Counter

app = FastAPI()

#Permanent AWS S3 URL (No expiration)
COMMON_PASSWORDS_URL = "https://uc2st10.s3.eu-north-1.amazonaws.com/Common_passwords.txt"

class PasswordInput(BaseModel):
    password: str

def password_meter(password):
    password_lower = password.strip().lower()

    if password_lower in common_passwords:
        return {
            "score": 0,
            "strength": "Very Weak",
            "feedback": ["Your password is in a common list. Choose a unique one."]
        }

    score = 0
    feedback = []
    length = len(password)

    if length >= 16: score += 3
    elif length >= 12: score += 2
    elif length >= 8: score += 1
    else: feedback.append("Use at least 12 characters.")

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    if not has_upper: feedback.append("Add an uppercase letter.")
    if not has_lower: feedback.append("Add a lowercase letter.")
    if not has_digit: feedback.append("Add a number.")
    if not has_special: feedback.append("Add a special character (@%$!^).")

    score += sum([has_upper, has_lower, has_digit, has_special])

    char_counts = Counter(password)
    if any(count > length / 2 for count in char_counts.values()):
        feedback.append("Avoid excessive repetition.")
        score -= 1

    common_patterns = ["123", "abc", "qwerty", "password", "letmein"]
    if any(pattern in password_lower for pattern in common_patterns):
        feedback.append("Avoid common patterns like '123', 'abc', or 'qwerty'.")
        score -= 1

    score = max(score, 0)

    strength = "Weak"
    if score >= 7: strength = "Very Strong"
    elif score >= 5: strength = "Strong"
    elif score >= 3: strength = "Medium"

    return {"score": score, "strength": strength, "feedback": feedback}

@app.post("/check_password/")
def check_password(data: PasswordInput):
    return password_meter(data.password)

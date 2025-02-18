import requests
from flask import Flask, request, jsonify
import re
import string
from collections import Counter

# Flask App
app = Flask(__name__)

# Corrected Dropbox Direct Download URL
COMMON_PASSWORDS_URL = "https://www.dropbox.com/scl/fi/mssepsyojl2xd8pva1fga/Common_passwords.txt?rlkey=but75iv17emzie71xmbp5tccv&dl=1"

def download_common_passwords():
    try:
        response = requests.get(COMMON_PASSWORDS_URL)
        response.raise_for_status()  # Raise error for failed requests
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:  # Fixed typo
        print(f"Error Downloading common_passwords.txt: {e}")
        return []

# Load common passwords from Dropbox
Common_passwords = download_common_passwords()

def password_meter(password, Common_passwords):
    password_lower = password.strip().lower()
    Common_passwords_lower = {p.strip().lower() for p in Common_passwords}

    if password_lower in Common_passwords_lower:
        return {
            "score": 0,
            "strength": "Very Weak",
            "feedback": ["Your password was found in a common passwords list and is vulnerable to attacks."]
        }

    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password is too short. Use at least 12 characters")

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    if has_upper:
        score += 1
    else:
        feedback.append("Add an uppercase letter")

    if has_lower:
        score += 1
    else:
        feedback.append("Add a lowercase letter")

    if has_digit:
        score += 1
    else:
        feedback.append("Add a number")

    if has_special:
        score += 1
    else:
        feedback.append("Add a special character (@%$!^)")

    char_counts = Counter(password)
    if any(count > len(password) / 2 for count in char_counts.values()):
        feedback.append("Avoid repeated characters too often.")
        score -= 1

    if re.search(r"(123|abc|qwerty|password)", password.lower()):
        feedback.append("Avoid common patterns like '123', 'abc', or 'qwerty'.")
        score -= 1

    strength = "Strong" if score >= 6 else "Medium" if score >= 3 else "Weak"

    return {"score": score, "strength": strength, "feedback": feedback}

@app.route('/')
def home():
    return "Password Strength Meter API. Send a POST request to /check-password with JSON { 'password': 'yourpassword' }"

@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.json
    password = data.get('password', '')
    result = password_meter(password, Common_passwords)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

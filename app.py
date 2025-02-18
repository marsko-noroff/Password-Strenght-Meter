import requests
from flask import Flask, request, jsonify, render_template
import re
import string
from collections import Counter

app = Flask(__name__)

# ✅ Use permanent AWS S3 URL (No expiration)
COMMON_PASSWORDS_URL = "https://uc2st10.s3.eu-north-1.amazonaws.com/Common_passwords.txt"

def is_common_password(password):
    """ Check if a password exists in the common passwords file using streaming. """
    try:
        response = requests.get(COMMON_PASSWORDS_URL, stream=True)
        response.raise_for_status()

        password_lower = password.strip().lower()  # Convert to lowercase for case-insensitive checking
        
        # Stream through file line by line (NO large memory usage)
        for line in response.iter_lines(decode_unicode=True):
            if line.strip().lower() == password_lower:
                return True  # Password found

    except requests.exceptions.RequestException as e:
        print(f"❌ Error downloading Common_passwords.txt: {e}")

    return False  # Password not found

def password_meter(password):
    """ Check password strength while avoiding large memory usage. """
    
    # ✅ Check if the password is in the common passwords file
    if is_common_password(password):
        return {
            "score": 0,
            "strength": "Very Weak",
            "feedback": ["Your password was found in a common passwords list and is vulnerable to attacks."]
        }

    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password is too short. Use at least 12 characters")

    # Complexity check
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

    # Repeated characters check
    char_counts = Counter(password)
    if any(count > len(password) / 2 for count in char_counts.values()):
        feedback.append("Avoid repeated characters too often.")
        score -= 1

    # Common pattern check
    if re.search(r"(123|abc|qwerty|password)", password.lower()):
        feedback.append("Avoid common patterns like '123', 'abc', or 'qwerty'.")
        score -= 1

    strength = "Strong" if score >= 6 else "Medium" if score >= 3 else "Weak"

    return {"score": score, "strength": strength, "feedback": feedback}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.json
    password = data.get('password', '')
    result = password_meter(password)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

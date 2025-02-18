import requests
from flask import Flask, request, jsonify, render_template
import re
import string
from collections import Counter

app = Flask(__name__)

COMMON_PASSWORDS_FILE_ID = "18PTFB31yc7rsx2N_okhq9Ri3h-EVfjlz"

def download_common_passwords():
    try:
        session = requests.Session()
        GOOGLE_DRIVE_URL = "https://drive.google.com/uc?export=download"

        response = session.get(GOOGLE_DRIVE_URL, params={"id": COMMON_PASSWORDS_FILE_ID}, stream=True)

        # Extract Google’s security confirmation token
        token = None
        for key, value in response.cookies.items():
            if key.startswith("download_warning"):
                token = value

        # Retry with confirmation token if needed
        if token:
            params = {"id": COMMON_PASSWORDS_FILE_ID, "confirm": token}
            response = session.get(GOOGLE_DRIVE_URL, params=params, stream=True)

        response.raise_for_status()

        # Read file line by line to handle large files
        common_passwords = []
        for line in response.iter_lines(decode_unicode=True):
            common_passwords.append(line.strip().lower())  # Convert to lowercase for case-insensitive comparison

        print("✅ Loaded Common Passwords (First 10):", common_passwords[:10])  # Debugging print

        return common_passwords

    except requests.exceptions.RequestException as e:
        print(f"❌ Error downloading Common_passwords.txt: {e}")
        return []

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
    return render_template('index.html')

@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.json
    password = data.get('password', '')
    result = password_meter(password, Common_passwords)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

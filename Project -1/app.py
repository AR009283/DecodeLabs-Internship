from flask import Flask, render_template, request, jsonify
import string

app = Flask(__name__)


# Load common passwords
def load_common_passwords():
    try:
        with open("common_passwords.txt", "r") as file:
            return file.read().splitlines()
    except FileNotFoundError:
        return []


common_passwords = load_common_passwords()


def check_password_strength(password):

    score = 0
    suggestions = []

    # Check common passwords
    if password.lower() in common_passwords:
        return {
            "strength": "Very Weak",
            "score": 0,
            "suggestions": [
                "This password is commonly used.",
                "Choose a unique password."
            ]
        }


    # Length check
    if len(password) >= 8:
        score += 20
    else:
        suggestions.append(
            "Password should contain at least 8 characters."
        )


    # Uppercase check
    if any(char.isupper() for char in password):
        score += 20
    else:
        suggestions.append(
            "Add uppercase letters."
        )


    # Lowercase check
    if any(char.islower() for char in password):
        score += 20
    else:
        suggestions.append(
            "Add lowercase letters."
        )


    # Number check
    if any(char.isdigit() for char in password):
        score += 20
    else:
        suggestions.append(
            "Add numbers."
        )


    # Symbol check
    if any(char in string.punctuation for char in password):
        score += 20
    else:
        suggestions.append(
            "Add special characters."
        )


    # Decide strength

    if score <= 40:
        strength = "Weak"

    elif score <= 80:
        strength = "Medium"

    else:
        strength = "Strong"


    return {
        "strength": strength,
        "score": score,
        "suggestions": suggestions
    }



@app.route("/")
def home():
    return render_template("index.html")



@app.route("/check", methods=["POST"])
def check():

    data = request.json

    password = data.get("password")


    result = check_password_strength(password)


    return jsonify(result)



if __name__ == "__main__":
    app.run(debug=True)
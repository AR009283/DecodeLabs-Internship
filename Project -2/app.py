from flask import Flask, render_template, request

app = Flask(__name__)

def encrypt(text, shift):
    result = ""

    for char in text:

        if char.isalpha():

            start = ord('A') if char.isupper() else ord('a')

            result += chr((ord(char)-start+shift)%26+start)

        else:
            result += char

    return result


def decrypt(text, shift):
    return encrypt(text, -shift)


@app.route("/", methods=["GET","POST"])
def index():

    encrypted = ""
    decrypted = ""
    text = ""
    shift = 3

    if request.method == "POST":

        text = request.form["text"]

        shift = int(request.form["shift"])

        encrypted = encrypt(text, shift)

        decrypted = decrypt(encrypted, shift)

    return render_template(
        "index.html",
        text=text,
        encrypted=encrypted,
        decrypted=decrypted,
        shift=shift
    )


if __name__ == "__main__":
    app.run(debug=True)
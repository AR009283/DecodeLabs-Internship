# 🔐 Basic Encryption & Decryption

A modern Flask-based web application that demonstrates the fundamentals of encryption and decryption using the Caesar Cipher algorithm.

This project was developed as **Project 2** for the **DecodeLabs Cyber Security Internship Program**.

---

## 📌 Project Overview

The application allows users to:

- Enter any text
- Choose a custom shift key
- Encrypt the text using the Caesar Cipher
- Decrypt the encrypted text back to the original
- Display both encrypted and decrypted outputs instantly

This project introduces the basic concepts of cryptography and secure data transformation.

---

## 🚀 Features

- 🔐 Caesar Cipher Encryption
- 🔓 Caesar Cipher Decryption
- 🔢 Custom Shift Key (1–25)
- 💻 Modern Responsive Web Interface
- ⚡ Real-Time Processing
- 🎨 Clean and User-Friendly Design
- 📱 Mobile Friendly
- 🔤 Supports Uppercase and Lowercase Letters
- 🔄 Preserves Numbers, Spaces, and Symbols

---

## 🛠 Technologies Used

- Python 3
- Flask
- HTML5
- CSS3
- JavaScript

---

## 📂 Project Structure

```
Basic-Encryption-Decryption/
│
├── app.py
├── requirements.txt
├── README.md
│
├── static/
│   ├── style.css
│   └── script.js
│
└── templates/
    └── index.html
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/Basic-Encryption-Decryption.git
```

Navigate into the project folder:

```bash
cd Basic-Encryption-Decryption
```

Create a virtual environment:

### Windows

```bash
python -m venv .venv
```

Activate the virtual environment:

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Run the Application

```bash
python app.py
```

Open your browser and visit:

```
http://127.0.0.1:5000
```

---

## 📖 How It Works

1. Enter the text you want to encrypt.
2. Select a shift value between 1 and 25.
3. Click the **Encrypt & Decrypt** button.
4. The application generates:
   - Encrypted Text
   - Decrypted Text

---

## 💡 Example

Input

```
Hello DecodeLabs
```

Shift Key

```
3
```

Encrypted Output

```
Khoor GhfrghOdev
```

Decrypted Output

```
Hello DecodeLabs
```

---

## 🔒 Caesar Cipher

The Caesar Cipher is one of the earliest and simplest encryption techniques.

Each letter in the plaintext is shifted by a fixed number of positions in the alphabet.

Example:

```
A → D
B → E
C → F
```

Using a shift value of **3**:

```
HELLO
↓

KHOOR
```

To decrypt, the same shift value is applied in the opposite direction.

---

## 📚 Learning Outcomes

Through this project, you will learn:

- Fundamentals of Cryptography
- Caesar Cipher Algorithm
- Encryption and Decryption Logic
- String Manipulation in Python
- Flask Web Development
- HTML Forms
- Python Functions
- Secure Data Handling Concepts

---

## 📸 Screenshots

Add screenshots of your application here after completion.

Example:

```
screenshots/home.png

screenshots/result.png
```

---

## 🎯 Future Improvements

- AES Encryption
- Vigenère Cipher
- File Encryption
- Text File Upload
- Copy to Clipboard
- Download Encrypted Text
- Encryption History
- Dark/Light Mode
- Multiple Encryption Algorithms

---

## 👨‍💻 Author

Developed by **Anu**

Cyber Security Intern — DecodeLabs

---

## 📄 License

This project is developed for educational and learning purposes as part of the DecodeLabs Cyber Security Internship Program.

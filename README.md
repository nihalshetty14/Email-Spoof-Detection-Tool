# 📧 Email Spoof Detection Tool

A Python-based command-line utility designed to analyze email headers and detect possible **email spoofing attempts**. It checks for **SPF**, **DKIM**, and **DMARC** results to assess authenticity and helps users understand whether an email is legitimate or forged.

---

## 🚀 Features

- ✅ Parses raw email headers from `.txt` files  
- ✅ Extracts and verifies SPF, DKIM, and DMARC status  
- ✅ Detects mismatches between "From", "Return-Path", and "Received" fields  
- ✅ Color-coded terminal output using `colorama`  
- ✅ Real-world test cases from Gmail and newsletter providers  
- 🧪 Multiple test headers supported in a single run  

---

## 📂 Project Structure

Email-Spoof-Detection-Tool/  
│  
├── main.py            # Main CLI entry point  
├── spoof_check.py     # Spoof analysis logic  
├── utils.py           # Helper functions (e.g., field extraction)  
├── test_cases/        # Real-world email header test files  
│   ├── sample1.txt  
│   └── sample2.txt  
└── README.md          # You're here!

---

## ⚙️ Requirements

Install dependencies via pip:

    pip install colorama

---

## 🧪 How to Use (CLI)

Analyze a single header file:

    python main.py test_cases/sample1.txt

Analyze all headers in the test_cases folder:

    python main.py test_cases/

---

## 📌 Sample Output

    Analyzing: sample1.txt  
    ✔ SPF: PASS  
    ✔ DKIM: PASS  
    ✔ DMARC: PASS  
    ✔ Header Consistency: MATCH  
    ➡️ Verdict: ✅ This email is likely legitimate.

---

## 📥 Sample Test Cases

- ✔ Gmail notification from GitHub (SPF/DKIM/DMARC pass)  
- ❌ Spoofed sender mismatch (From vs Return-Path mismatch)  
- ⚠️ Missing SPF or DMARC headers

---

## 📄 License

This project is open-source and available under the MIT License.

---

## 🙋 Author

👨‍💻 Nihal Shetty  
🔐 Cybersecurity & IoT Enthusiast | Final Year B.E. Student  
🌟 GitHub: [@nihalshetty14](https://github.com/nihalshetty14)  
🔗 LinkedIn: [linkedin.com/in/nihalshetty0814](https://www.linkedin.com/in/nihalshetty0814)  
✉️ Email: nihalshetty.0814@gmail.com

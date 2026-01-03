Hash Identifier 🔐

A professional cryptographic hash IDENTIFICATION tool that detects the most likely
hash algorithm using length, patterns, prefixes, and encoding heuristics.
Perfect for cybersecurity researchers, pentesters, developers, and students.

GitHub: https://github.com/CyberBros435/Hash_Identifier

Made by: Cyber Bro's

---

FEATURES ✨

✅ Supports 12+ Hash Algorithms (Identification):
- MD5
- SHA1
- SHA224, SHA256, SHA384, SHA512
- SHA3-224, SHA3-256, SHA3-384, SHA3-512
- BLAKE2b, BLAKE2s

✅ Password Hash Detection:
- bcrypt
- argon2 (argon2id / argon2i / argon2d)
- scrypt
- PBKDF2 (framework formats)
- phpass (WordPress / Drupal)
- Unix crypt formats ($1$, $5$, $6$)

✅ Colorful CLI Interface with ASCII banner (pyfiglet)
✅ Confidence-Based Detection (Top match + alternatives)
✅ Shows hash length, charset, entropy & evidence
✅ Hacker-style loading animation
✅ Save results to readable .txt report
✅ Beginner & Professional friendly

---

IMPORTANT NOTE ⚠️

Some hashes share the SAME output length.

Example:
- 64 hex characters can be:
  SHA256 OR SHA3-256 OR BLAKE2s

Because of this, the tool shows POSSIBLE matches with confidence.
100% confirmation requires knowing the source system
(database, OS, application, framework, etc.).

---

REQUIREMENTS 📦

- Python 3.13.9
- pip (Python package manager)
- Git

---

INSTALLATION 📥

---

WINDOWS INSTALLATION ⚙️

Step 1: Install Python
Download from:
https://www.python.org/downloads/

IMPORTANT:
During installation ENABLE:
[✓] Add Python to PATH

Step 2: Clone Repository
git clone https://github.com/CyberBros435/Hash_Identifier.git
cd Hash_Identifier

Step 3: Install Dependencies
pip install -r requirements.txt

Step 4: Run Tool
python Hash_Identifier.py

If python command does not work:
py Hash_Identifier.py

---

LINUX INSTALLATION 🐧 (Ubuntu / Debian / Kali / Arch)

Step 1: Install Python & pip

Debian / Ubuntu / Kali:
sudo apt update
sudo apt install -y python3 python3-pip

Arch:
sudo pacman -S python python-pip

Step 2: Clone Repository
git clone https://github.com/CyberBros435/Hash_Identifier.git
cd Hash_Identifier

Step 3: Install Dependencies
pip3 install -r requirements.txt

Step 4: Run Tool
python3 Hash_Identifier.py

Optional (Make Executable):
chmod +x Hash_Identifier.py
./Hash_Identifier.py

---

macOS INSTALLATION 🍎

Step 1: Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Step 2: Install Python
brew install python

Step 3: Clone Repository
git clone https://github.com/CyberBros435/Hash_Identifier.git
cd Hash_Identifier

Step 4: Install Dependencies
pip3 install -r requirements.txt

Step 5: Run Tool
python3 Hash_Identifier.py

---

TERMUX INSTALLATION 📱 (Android)

Step 1: Update Packages
pkg update && pkg upgrade -y

Step 2: Install Python & Git
pkg install -y python git

Step 3: Clone Repository
git clone https://github.com/CyberBros435/Hash_Identifier.git
cd Hash_Identifier

Step 4: Install Dependencies
pip install -r requirements.txt

Step 5: Run Tool
python Hash_Identifier.py

---

QUICK START ⚡ (All Systems)

git clone https://github.com/CyberBros435/Hash_Identifier.git && \
cd Hash_Identifier && \
pip install -r requirements.txt && \
python Hash_Identifier.py

---

USAGE 🚀

Run the tool:
python Hash_Identifier.py

How it works:
1. Tool starts with professional ASCII banner
2. Paste your hash
3. Tool analyzes and shows:
   - Hash length
   - Character set
   - Entropy estimate
   - Top match with confidence
   - Other possible hash types
4. Choose Y / N to save report

---

EXAMPLE OUTPUT 📋

Input        : 5f4dcc3b5aa765d61d8327deb882cf99
Length       : 32
Charset      : hex (lowercase)
Entropy      : 3.99 bits/char

TOP MATCH:
Type         : MD5
Confidence   : 82%
Category     : Message digest

OTHER POSSIBLE TYPES:
- NTLM

---

SAVING REPORTS 💾

If you choose YES, the tool creates a file:

hash_report_<hash>_<timestamp>.txt

Location:
Same directory as Hash_Identifier.py

---

FILE STRUCTURE 📁

Hash_Identifier/
├── Hash_Identifier.py
├── requirements.txt
├── README.md
└── .gitignore

---

TROUBLESHOOTING 🔧

Issue: ModuleNotFoundError
Solution:
pip install -r requirements.txt

Issue: Python command not found
Solution:
python --version

Reinstall Python and enable:
Add Python to PATH

---

LICENSE 📜

No license yet.

---

AUTHOR 👨‍💻

Cyber Bro's

GitHub:
https://github.com/CyberBros435

---

SUPPORT 💬

If you find this tool useful:
- ⭐ Star the repository
- 🔗 Share with others
- 🐞 Report bugs or suggest features

---

CHANGELOG 📝

v1.0 (Initial Release)
- Support for 12+ hash algorithms
- Password hash format detection
- Colorful CLI interface
- Confidence-based identification
- Saveable readable reports
- Complete documentation

---

Happy Hash Identifying! 🔐✨

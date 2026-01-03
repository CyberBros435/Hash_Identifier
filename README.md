# Hash Identifier 🔐

A professional cryptographic **hash identification tool** that detects the most likely
hash algorithm using **length, patterns, prefixes, and encoding heuristics**.
Perfect for **cybersecurity researchers, pentesters, developers, and students**.

**GitHub:** https://github.com/CyberBros435/Hash_Identifier  
**Made by:** Cyber Bro's

---

## Features ✨

✅ **Supports 12+ Hash Algorithms (Identification):**
- MD5
- SHA1
- SHA224, SHA256, SHA384, SHA512
- SHA3-224, SHA3-256, SHA3-384, SHA3-512
- BLAKE2b, BLAKE2s

✅ **Password Hash Detection**
- bcrypt
- argon2 (argon2id / argon2i / argon2d)
- scrypt
- PBKDF2 formats
- phpass (WordPress / Drupal)
- Unix crypt (`$1$`, `$5$`, `$6$`)

✅ **Colorful CLI Interface** (pyfiglet banner)  
✅ **Confidence-Based Detection** (Top match + alternatives)  
✅ **Readable Output** (length, charset, entropy, evidence)  
✅ **Hacker-style Loading Animation**  
✅ **Save Results to `.txt` File**  

---

## Important Note ⚠️

Some hashes share the **same output length**.

Example:
- 64 hex characters can be:
  - SHA256
  - SHA3-256
  - BLAKE2s

Because of this, the tool shows **possible matches with confidence**.
**100% confirmation requires source context** (database, OS, application, framework).

---

## Requirements 📦

- Python **3.13.9**
- pip (Python package manager)
- Git

---

## Installation 📥

---

### ⚙️ Windows Installation

**Step 1: Install Python**
- Download from: https://www.python.org/downloads/
- ✅ Enable **Add Python to PATH**

**Step 2: Clone Repository**
```cmd
git clone https://github.com/CyberBros435/Hash_Identifier.git
cd Hash_Identifier
```

**Step 3: Install Dependencies**
```cmd
pip install -r requirements.txt
```

**Step 4: Run Tool**
```cmd
python Hash_Identifier.py
```

If `python` doesn’t work:
```cmd
py Hash_Identifier.py
```

---

### 🐧 Linux Installation (Ubuntu / Debian / Kali / Arch)

**Step 1: Install Python & pip**

Debian / Ubuntu / Kali:
```bash
sudo apt update
sudo apt install -y python3 python3-pip
```

Arch:
```bash
sudo pacman -S python python-pip
```

**Step 2: Clone Repository**
```bash
git clone https://github.com/CyberBros435/Hash_Identifier.git
cd Hash_Identifier
```

**Step 3: Install Dependencies**
```bash
pip3 install -r requirements.txt
```

**Step 4: Run Tool**
```bash
python3 Hash_Identifier.py
```

**Optional: Make Executable**
```bash
chmod +x Hash_Identifier.py
./Hash_Identifier.py
```

---

### 🍎 macOS Installation

**Step 1: Install Homebrew (if not installed)**
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Step 2: Install Python**
```bash
brew install python
```

**Step 3: Clone Repository**
```bash
git clone https://github.com/CyberBros435/Hash_Identifier.git
cd Hash_Identifier
```

**Step 4: Install Dependencies**
```bash
pip3 install -r requirements.txt
```

**Step 5: Run Tool**
```bash
python3 Hash_Identifier.py
```

---

### 📱 Termux Installation (Android)

**Step 1: Update Packages**
```bash
pkg update && pkg upgrade -y
```

**Step 2: Install Python & Git**
```bash
pkg install -y python git
```

**Step 3: Clone Repository**
```bash
git clone https://github.com/CyberBros435/Hash_Identifier.git
cd Hash_Identifier
```

**Step 4: Install Dependencies**
```bash
pip install -r requirements.txt
```

**Step 5: Run Tool**
```bash
python Hash_Identifier.py
```

---

### ⚡ Quick Start (All Systems)

```bash
git clone https://github.com/CyberBros435/Hash_Identifier.git && \
cd Hash_Identifier && \
pip install -r requirements.txt && \
python Hash_Identifier.py
```

---

## Usage 🚀

**Run the Tool**
```bash
python Hash_Identifier.py
```

**How It Works**
1. Tool starts with professional ASCII banner
2. Paste your hash
3. Tool analyzes and displays:
   - Hash length
   - Character set
   - Entropy estimate
   - Top match with confidence
   - Other possible hash types
4. Choose **Y / N** to save the report

---

## Example Output 📋

```
Input        : 5f4dcc3b5aa765d61d8327deb882cf99
Length       : 32
Charset      : hex (lowercase)
Entropy      : 3.99 bits/char

TOP MATCH:
Type         : MD5
Confidence   : 82%
Category     : Message digest
```

---

## Saving Reports 💾

If you select **YES**, the tool creates:

```
hash_report_<hash>_<timestamp>.txt
```

📁 Saved in the same directory as `Hash_Identifier.py`

---

## File Structure 📁

```
Hash_Identifier/
├── Hash_Identifier.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Troubleshooting 🔧

**Module not found**
```bash
pip install -r requirements.txt
```

**Python not found**
```bash
python --version
```
Reinstall Python and enable **Add Python to PATH**

---

## License 📜

No license yet.

---

## Author 👨‍💻

**Cyber Bro's**

GitHub: https://github.com/CyberBros435

---

## Support ⭐

If you find this tool useful:
- ⭐ Star the repository
- 🔗 Share with others
- 🐞 Report bugs or ideas

---

## Changelog 📝

### v1.0
- Support for 12+ hash algorithms
- Password hash format detection
- Colorful CLI interface
- Confidence-based identification
- Saveable readable reports
- Complete documentation

---

**Happy Hash Identifying! 🔐**

Hash Identifier (CLI)
====================

Hash Identifier is a colorful and easy-to-use CLI tool that helps identify
the most likely hash type based on length, patterns, and encoding hints.

Made by: Cyber Bro's

------------------------------------------------------------
FEATURES
------------------------------------------------------------

- Professional ASCII banner using pyfiglet
- Supports major hash families:
  md5
  sha1
  sha224
  sha256
  sha384
  sha512
  sha3_224
  sha3_256
  sha3_384
  sha3_512
  blake2b
  blake2s

- Detects common password hash formats:
  bcrypt
  argon2 (argon2id / argon2i / argon2d)
  scrypt
  PBKDF2 (framework formats)
  phpass (WordPress / Drupal)
  Unix crypt formats ($1$, $5$, $6$)

- Clean, readable output
- Confidence-based ranking
- Hacker-style loading animation
- Option to save results to .txt file

------------------------------------------------------------
IMPORTANT NOTE
------------------------------------------------------------

Some hashes share the same output length.
Example:
- 64 hex characters can be:
  sha256 OR sha3_256 OR blake2s

Because of this, the tool shows POSSIBLE matches with confidence.
Exact confirmation may require knowing the source system.

------------------------------------------------------------
REQUIREMENTS
------------------------------------------------------------

- Python 3.13.9
- pip package manager

------------------------------------------------------------
DOWNLOAD / CLONE
------------------------------------------------------------

GitHub Repository:
https://github.com/CyberBros435/Hash_Identifier

Clone using git:
git clone https://github.com/CyberBros435/Hash_Identifier.git

Go to project folder:
cd Hash_Identifier

------------------------------------------------------------
LINUX (Ubuntu / Debian / Kali / Arch)
------------------------------------------------------------

Install Python & pip (Debian / Ubuntu / Kali):
sudo apt update
sudo apt install -y python3 python3-pip

Install Python & pip (Arch):
sudo pacman -S python python-pip

Install dependencies:
pip3 install -r requirements.txt

Run tool:
python3 Hash_Identifier.py

------------------------------------------------------------
macOS
------------------------------------------------------------

Install Homebrew (if not installed):
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Install Python:
brew install python

Install dependencies:
pip3 install -r requirements.txt

Run tool:
python3 Hash_Identifier.py

------------------------------------------------------------
WINDOWS (PowerShell / CMD)
------------------------------------------------------------

1) Download Python from:
https://www.python.org/downloads/

IMPORTANT:
During installation, ENABLE:
"Add Python to PATH"

Open PowerShell in project folder

Install dependencies:
pip install -r requirements.txt

Run tool:
python Hash_Identifier.py

If python command does not work:
py Hash_Identifier.py

------------------------------------------------------------
TERMUX (Android)
------------------------------------------------------------

Update packages:
pkg update && pkg upgrade -y

Install Python & Git:
pkg install -y python git

Clone repository:
git clone https://github.com/CyberBros435/Hash_Identifier.git

Go to project folder:
cd Hash_Identifier

Install dependencies:
pip install -r requirements.txt

Run tool:
python Hash_Identifier.py

------------------------------------------------------------
USAGE
------------------------------------------------------------

1) Run the tool
2) Paste the hash
3) Tool shows:
   - Length
   - Charset
   - Entropy estimate
   - Top match + confidence
4) Choose Y/N to save report

------------------------------------------------------------
SAVING OUTPUT
------------------------------------------------------------

If you choose YES, a file will be created:

hash_report_<hash>_<timestamp>.txt

Location:
Same folder as Hash_Identifier.py

------------------------------------------------------------
TROUBLESHOOTING
------------------------------------------------------------

pip command not found (Linux):
sudo apt install -y python3-pip

Module not found error:
pip install -r requirements.txt

Windows python not recognized:
Reinstall Python and enable "Add Python to PATH"

------------------------------------------------------------
LICENSE
------------------------------------------------------------

No license yet.

------------------------------------------------------------
AUTHOR
------------------------------------------------------------

Cyber Bro's

GitHub:
https://github.com/CyberBros435

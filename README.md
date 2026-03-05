<div align="center">

```
  _   _           _     ___    _            _   _  __ _           
 | | | | __ _ ___| |__ |_ _|__| | ___ _ __ | |_(_)/ _(_) ___ _ __ 
 | |_| |/ _` / __| '_ \ | |/ _` |/ _ \ '_ \| __| | |_| |/ _ \ '__|
 |  _  | (_| \__ \ | | || | (_| |  __/ | | | |_| |  _| |  __/ |   
 |_| |_|\__,_|___/_| |_|___\__,_|\___|_| |_|\__|_|_| |_|\___|_|   
```

# 🔎 Hash Identifier — CLI Hash Type Detection

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen?style=flat-square)]()
[![Author](https://img.shields.io/badge/Author-Mudasir%20Zia-purple?style=flat-square)](https://github.com/CyberBros435)

> **A smart, terminal-based hash type detection tool built in Python.**  
> Paste any unknown hash — get instant analysis, confidence scores, and a full candidate list.  
> Built for CTF players, forensic analysts, and security researchers.

</div>

---

## 📌 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Detectable Hash Types](#-detectable-hash-types)
- [Requirements](#-requirements)
- [Quick Install (One Command)](#-quick-install-one-command)
- [Step-by-Step Installation](#-step-by-step-installation)
- [Usage](#-usage)
- [Example Session](#-example-session)
- [How It Works](#-how-it-works)
- [Output Report Fields](#-output-report-fields)
- [Project Structure](#-project-structure)
- [Related Projects](#-related-projects)
- [Author](#-author)
- [Disclaimer](#-disclaimer)

---

## 🧠 About

**Hash Identifier** is a Python CLI tool that analyzes an unknown hash string and identifies its most likely algorithm — with a confidence score, supporting evidence, and a ranked list of all possible candidates.

It uses a two-layer detection engine: **regex-based rule matching** for structured formats (bcrypt, Argon2, JWT, etc.) and **heuristic length/charset analysis** for raw digest families (MD5, SHA-256, BLAKE2, etc.).

Results can be **saved as a plain-text report** in the same directory as the script.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔎 **Smart Detection** | Two-layer engine: regex rules + heuristic analysis |
| 📊 **Confidence Scores** | Color-coded confidence percentage per candidate |
| 📋 **Ranked Candidates** | Up to 12 possible hash types listed with evidence |
| 🧮 **Entropy Analysis** | Shannon entropy calculated per input |
| 💾 **Save Reports** | Export clean plain-text `.txt` reports to disk |
| 🎭 **Hash Masking** | Input is masked in output to protect sensitive data |
| ⚡ **Hacker Loading** | Animated terminal spinner during analysis |
| 🎨 **Colorized CLI** | Rich color-coded output via `colorama` |

---

## 🔐 Detectable Hash Types

### Digest Families (Heuristic)

| Algorithm | Hex Length | Notes |
|---|---|---|
| MD5 | 32 | Also matches NTLM |
| SHA-1 | 40 | |
| SHA-224 / SHA3-224 | 56 | Ambiguous — same length |
| SHA-256 / SHA3-256 / BLAKE2s | 64 | Ambiguous — same length |
| SHA-384 / SHA3-384 | 96 | Ambiguous — same length |
| SHA-512 / SHA3-512 / BLAKE2b | 128 | Ambiguous — same length |
| NTLM (MD4) | 32 | Windows password hash |
| LM Hash | 32 | Legacy Windows |

### Structured / Password Formats (Regex Rules)

| Format | Example Prefix | Category |
|---|---|---|
| bcrypt | `$2a$` / `$2b$` / `$2y$` | Adaptive password hash |
| Argon2 | `$argon2id$` | Modern KDF |
| scrypt | `$scrypt$` | Adaptive KDF |
| PBKDF2 | `pbkdf2_sha256$` | KDF (Django etc.) |
| phpass | `$P$` / `$H$` | WordPress/Drupal |
| MD5 crypt | `$1$` | Unix/Cisco type 5 |
| APR1 | `$apr1$` | Apache htpasswd |
| SHA-256 crypt | `$5$` | Unix shadow |
| SHA-512 crypt | `$6$` | Unix shadow |
| MySQL 4.1+ | `*` + 40 hex | Database |
| UUID | `xxxxxxxx-xxxx-xxxx` | Identifier (not a hash) |
| JWT | `header.payload.sig` | Token (not a hash) |

---

## ⚙️ Requirements

- **OS:** Windows / Linux / macOS (cross-platform)
- **Python:** 3.7 or higher
- **Dependencies:**

```
colorama==0.4.6
pyfiglet==1.0.2
```

---

## ⚡ Quick Install (One Command)

```bash
git clone https://github.com/CyberBros435/Hash_Identifier.git && cd Hash_Identifier && pip install -r requirements.txt
```

Then run:

```bash
python main.py
```

---

## 🛠️ Step-by-Step Installation

### 1. Clone the Repository

```bash
git clone https://github.com/CyberBros435/Hash_Identifier.git
```

### 2. Navigate into the Project Directory

```bash
cd Hash_Identifier
```

### 3. (Optional) Create a Virtual Environment

```bash
python -m venv venv
```

Activate it:

```bash
# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install colorama==0.4.6 pyfiglet==1.0.2
```

### 5. Run the Tool

```bash
python main.py
```

---

## 🚀 Usage

On launch, the banner and a list of example hashes are displayed. Paste any hash at the prompt:

```
Hash > 5f4dcc3b5aa765d61d8327deb882cf99
```

After analysis, you'll see a full report and be asked if you want to save it.

### Input Rules

| Input | Behavior |
|---|---|
| Any hash string | Analyzed and reported |
| Empty input | Rejected — prompts again |
| `q` / `exit` / `quit` | Exits the program |

---

## 💻 Example Session

```
Hash > 5f4dcc3b5aa765d61d8327deb882cf99

⠹ Analyzing hash [01abAB$./=+*#01ab...]

══════════════════════════════════════════════════════════════════════════════
ANALYSIS SUMMARY
══════════════════════════════════════════════════════════════════════════════
Input           : 5f4dcc3b****82cf99
Length          : 32
Charset         : lower, digits
Entropy         : 3.87 bits/char
──────────────────────────────────────────────────────────────────────────────
TOP MATCH
[TYPE] MD5   [CONF] 82%   [CAT] Message digest (hex/length heuristic)
[EVIDENCE] 32 hex chars (lowercase hex)
[NOTE] Cannot be 100% certain from length alone; source context improves accuracy.
──────────────────────────────────────────────────────────────────────────────
OTHER POSSIBLE TYPES
  1. MD5             • Message digest   • 82%
     ↳ 32 hex chars (lowercase hex)
  2. NTLM (MD4)      • Windows hash     • 78%
     ↳ NTLM is also 32 hex chars
══════════════════════════════════════════════════════════════════════════════

Save report to .txt (same folder as script)?
[Y]es / [N]o > y
Saved: /path/to/hash_report_5f4dcc3b_20250305_142301.txt
```

---

## 🔬 How It Works

The detection engine runs in two stages:

**Stage 1 — Rule-Based Matching**
Checks the input against 12+ regex patterns for structured hash formats (bcrypt, Argon2, JWT, MySQL, Unix crypt, etc.). These produce high-confidence matches (90–98%).

**Stage 2 — Heuristic Analysis**
If no rule matches, the engine inspects character length, charset composition, and Shannon entropy to identify raw digest families. Length ambiguities (e.g. SHA-256 vs SHA3-256 vs BLAKE2s are all 64 hex chars) are clearly flagged.

Both stages produce a ranked candidate list with individual confidence scores and supporting evidence strings.

---

## 📊 Output Report Fields

| Field | Description |
|---|---|
| `Input (masked)` | First 6 + last 4 chars shown, rest masked with `*` |
| `Length` | Total character length of the input |
| `Charset` | Character types present: lower, upper, digits, symbols |
| `Entropy` | Shannon entropy in bits per character |
| `Top Match` | Highest-confidence candidate with evidence and notes |
| `Other Types` | Up to 12 ranked alternatives with confidence scores |

---

## 📁 Project Structure

```
Hash_Identifier/
│
├── main.py               # Full detection engine + CLI interface
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation
```

---

## 🔗 Related Projects

> Part of the **CyberBros435** network & security toolkit collection:

| Tool | Description | Link |
|---|---|---|
| 🔍 **IP Scanner** | IPv4 scanner, ping, tracert & ipconfig | [CyberBros435/IP_Scanner](https://github.com/CyberBros435/IP_Scanner) |
| 🌐 **DNS Server** | Hostname to IPv4 resolver | [CyberBros435/DNS_Server](https://github.com/CyberBros435/DNS_Server) |
| #️⃣ **Hash Generator** | Text to hash converter | [CyberBros435/Hash_Generator](https://github.com/CyberBros435/Hash_Generator) |
| 🔎 **Hash Identifier** | Identify unknown hash types *(this repo)* | [CyberBros435/Hash_Identifier](https://github.com/CyberBros435/Hash_Identifier) |

---

## 👤 Author

**Mudasir Zia**  
🔗 GitHub: [@CyberBros435](https://github.com/CyberBros435)  
📦 Repository: [CyberBros435/Hash_Identifier](https://github.com/CyberBros435/Hash_Identifier)

---

## ⚠️ Disclaimer

> This tool is intended **for educational, forensic research, and authorized security use only.**  
> The author is **not responsible** for any misuse of this software.  
> Always ensure you have **explicit permission** before analyzing hashes from systems you do not own.

---

<div align="center">

Made with ❤️ by [Mudasir Zia](https://github.com/CyberBros435) · ⭐ Star this repo if you found it useful!

</div>

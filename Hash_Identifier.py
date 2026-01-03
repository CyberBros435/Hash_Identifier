#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hash Identifier (CLI) - Cyber Bro's
Upgraded:
- Covers common password hash formats + digest families including:
  md5, sha1, sha224, sha256, sha384, sha512,
  sha3_224, sha3_256, sha3_384, sha3_512,
  blake2b, blake2s
- Clean, very readable output
- Save report as clean plain-text (no ANSI codes) in same directory
"""

import os
import re
import sys
import time
from datetime import datetime

try:
    import pyfiglet
except ImportError:
    print("Missing dependency: pyfiglet\nInstall with: pip install pyfiglet")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    print("Missing dependency: colorama\nInstall with: pip install colorama")
    sys.exit(1)

colorama_init(autoreset=True)

APP_NAME = "Hash Identifier"
MADE_BY = "Cyber Bro's"

# -----------------------------
# Helpers: styling
# -----------------------------
def c(text, color=Fore.WHITE, bright=True):
    return (Style.BRIGHT if bright else "") + color + str(text) + Style.RESET_ALL


def hr(width=78, ch="─", color=Fore.BLUE):
    return c(ch * width, color)


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def pad_kv(key, val, k_width=16):
    return f"{c(key.ljust(k_width), Fore.CYAN)}: {c(val, Fore.WHITE, bright=False)}"


def badge(text, color):
    return c(f"[{text}]", color)


# -----------------------------
# “Hacker-style” loading
# -----------------------------
def hacker_loading(label="Analyzing", seconds=1.4):
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    charset = "01abcdefABCDEF$./=+*#@!?_"
    start = time.time()
    i = 0
    while time.time() - start < seconds:
        i += 1
        trail = "".join(charset[(i * 7 + j * 11) % len(charset)] for j in range(30))
        line = (
            f"{c(spinner[i % len(spinner)]+' ', Fore.GREEN)}"
            f"{c(label, Fore.WHITE)} "
            f"{c('[', Fore.BLUE)}{c(trail, Fore.GREEN, bright=False)}{c(']', Fore.BLUE)}"
        )
        sys.stdout.write("\r" + line + "   ")
        sys.stdout.flush()
        time.sleep(0.06)
    sys.stdout.write("\r" + " " * 120 + "\r")
    sys.stdout.flush()


# -----------------------------
# Detection utilities
# -----------------------------
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
LOW_HEX_RE = re.compile(r"^[0-9a-f]+$")


def is_hex(s: str) -> bool:
    return bool(HEX_RE.fullmatch(s))


def is_base64ish(s: str) -> bool:
    return bool(B64_RE.fullmatch(s)) and (len(s) % 4 == 0)


def is_digits(s: str) -> bool:
    return s.isdigit()


def mask_hash(s: str) -> str:
    s = s.strip()
    if len(s) <= 12:
        return s
    return s[:6] + ("*" * (len(s) - 10)) + s[-4:]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for count in freq.values():
        p = count / n
        ent -= p * log2(p)
    return ent


def charset_desc(s: str) -> str:
    tags = []
    if any(ch.islower() for ch in s):
        tags.append("lower")
    if any(ch.isupper() for ch in s):
        tags.append("upper")
    if any(ch.isdigit() for ch in s):
        tags.append("digits")
    if any(not ch.isalnum() for ch in s):
        tags.append("symbols")
    return ", ".join(tags) if tags else "unknown"


def confidence_color(conf: float):
    pct = int(round(conf * 100))
    if pct >= 85:
        return Fore.GREEN
    if pct >= 60:
        return Fore.YELLOW
    return Fore.RED


# -----------------------------
# Rules (prefix / structured formats)
# -----------------------------
RULES = [
    # Password KDF / Modular Crypt
    {
        "name": "bcrypt",
        "category": "Password hash (adaptive)",
        "regex": re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"),
        "confidence": 0.98,
        "evidence": "Prefix $2a/$2b/$2y with cost + 53-char payload",
        "notes": ["Very common for password storage."],
    },
    {
        "name": "Argon2 (argon2id/argon2i/argon2d)",
        "category": "Password hash (adaptive)",
        "regex": re.compile(
            r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$"
        ),
        "confidence": 0.97,
        "evidence": "Argon2 encoded string format ($argon2...$v=...$m=...,t=...,p=...$salt$hash)",
        "notes": ["Modern and strong password hashing scheme."],
    },
    {
        "name": "scrypt (modular crypt)",
        "category": "Password hash (adaptive)",
        "regex": re.compile(r"^\$scrypt\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$"),
        "confidence": 0.90,
        "evidence": "Looks like $scrypt$ modular format",
        "notes": [],
    },
    {
        "name": "PBKDF2 (framework format)",
        "category": "Password hash (KDF)",
        "regex": re.compile(r"^pbkdf2_(sha1|sha256|sha512)\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$"),
        "confidence": 0.90,
        "evidence": "pbkdf2_<algo>$<iterations>$<salt>$<hash>",
        "notes": ["Common in Django and other frameworks."],
    },
    {
        "name": "phpass (WordPress/Drupal)",
        "category": "Password hash (portable)",
        "regex": re.compile(r"^\$(P|H)\$[./0-9A-Za-z]{31}$"),
        "confidence": 0.92,
        "evidence": "Prefix $P$/$H$ + 31 chars",
        "notes": [],
    },
    {
        "name": "MD5 crypt ($1$) / Cisco type 5",
        "category": "Unix crypt / Network",
        "regex": re.compile(r"^\$1\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{22,}$"),
        "confidence": 0.93,
        "evidence": "Modular crypt $1$ format",
        "notes": ["Often seen in /etc/shadow or Cisco type 5."],
    },
    {
        "name": "APR1 (Apache MD5)",
        "category": "Web server auth",
        "regex": re.compile(r"^\$apr1\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{22,}$"),
        "confidence": 0.93,
        "evidence": "Modular crypt $apr1$ format (Apache htpasswd)",
        "notes": [],
    },
    {
        "name": "SHA-256 crypt ($5$)",
        "category": "Unix crypt",
        "regex": re.compile(r"^\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{20,}$"),
        "confidence": 0.93,
        "evidence": "Modular crypt $5$ format",
        "notes": [],
    },
    {
        "name": "SHA-512 crypt ($6$)",
        "category": "Unix crypt",
        "regex": re.compile(r"^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{40,}$"),
        "confidence": 0.93,
        "evidence": "Modular crypt $6$ format",
        "notes": [],
    },

    # Databases
    {
        "name": "MySQL 4.1+ password (SHA1)",
        "category": "Database password hash",
        "regex": re.compile(r"^\*[0-9A-F]{40}$"),
        "confidence": 0.95,
        "evidence": "Leading * followed by 40 uppercase hex chars",
        "notes": [],
    },

    # Tokens / identifiers confused with hashes
    {
        "name": "UUID (not a hash)",
        "category": "Identifier",
        "regex": re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"),
        "confidence": 0.95,
        "evidence": "Matches UUID v1–v5 pattern",
        "notes": ["Often mistaken as a hash due to randomness."],
    },
    {
        "name": "JWT (token, not a hash)",
        "category": "Token",
        "regex": re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),
        "confidence": 0.75,
        "evidence": "Three base64url-like segments separated by dots",
        "notes": ["JWT is a signed token: header.payload.signature."],
    },
]


# -----------------------------
# Heuristics (digest families)
# -----------------------------
def heuristic_candidates(s: str):
    cands = []
    length = len(s)
    ent = shannon_entropy(s)
    charset = charset_desc(s)

    if is_hex(s):
        casing_hint = "lowercase hex" if bool(LOW_HEX_RE.fullmatch(s)) else "mixed/uppercase hex"

        # ✅ Digest candidates (includes your requested list)
        # NOTE: Some share the same output length => ambiguous without context
        length_map = {
            32: [
                ("MD5", 0.82, "32 hex chars"),
                ("NTLM (MD4 of UTF-16LE password)", 0.78, "NTLM is also 32 hex chars"),
            ],
            40: [
                ("SHA-1", 0.86, "40 hex chars"),
            ],
            56: [
                ("SHA-224", 0.86, "56 hex chars"),
                ("SHA3-224", 0.82, "SHA3-224 is also 56 hex chars (same-length ambiguity)"),
            ],
            64: [
                ("SHA-256", 0.87, "64 hex chars"),
                ("SHA3-256", 0.83, "SHA3-256 is also 64 hex chars (same-length ambiguity)"),
                ("BLAKE2s", 0.80, "BLAKE2s is often 32 bytes => 64 hex chars (same-length ambiguity)"),
            ],
            96: [
                ("SHA-384", 0.87, "96 hex chars"),
                ("SHA3-384", 0.83, "SHA3-384 is also 96 hex chars (same-length ambiguity)"),
            ],
            128: [
                ("SHA-512", 0.87, "128 hex chars"),
                ("SHA3-512", 0.83, "SHA3-512 is also 128 hex chars (same-length ambiguity)"),
                ("BLAKE2b", 0.80, "BLAKE2b is often 64 bytes => 128 hex chars (same-length ambiguity)"),
            ],
        }

        if length in length_map:
            for name, conf, evidence in length_map[length]:
                notes = ["Cannot be 100% certain from length alone; source context improves accuracy."]
                if "ambiguity" in evidence:
                    notes.append("This length matches multiple algorithms. Check system/app context to confirm.")
                cands.append({
                    "name": name,
                    "category": "Message digest (hex/length heuristic)",
                    "confidence": conf,
                    "evidence": f"{evidence} ({casing_hint})",
                    "notes": notes,
                    "length": length,
                    "charset": charset,
                    "entropy": ent,
                })

        # LM clue (legacy)
        if length == 32 and s.upper().endswith("AAD3B435B51404EE"):
            cands.append({
                "name": "LM hash (one half empty pattern)",
                "category": "Windows legacy password hash",
                "confidence": 0.92,
                "evidence": "Ends with AAD3B435B51404EE (common LM empty half)",
                "notes": ["Often found alongside NTLM."],
                "length": length,
                "charset": charset,
                "entropy": ent,
            })

    # Base64 (encoding)
    if is_base64ish(s) and len(s) >= 16:
        cands.append({
            "name": "Base64-encoded data (encoding, not a hash type)",
            "category": "Encoding",
            "confidence": 0.55,
            "evidence": "Base64 charset + length multiple of 4",
            "notes": ["Could be a digest or random bytes encoded as Base64."],
            "length": len(s),
            "charset": charset,
            "entropy": ent,
        })

    # Pure digits (weak hint)
    if is_digits(s) and len(s) in (8, 10):
        cands.append({
            "name": "Numeric checksum / ID (possibly CRC32/other)",
            "category": "Checksum/Identifier",
            "confidence": 0.35,
            "evidence": "Only digits and short length",
            "notes": ["Not enough info to be sure; could be an ID."],
            "length": len(s),
            "charset": charset,
            "entropy": ent,
        })

    return cands


def classify_hash(user_input: str):
    s = user_input.strip()
    length = len(s)
    ent = shannon_entropy(s)
    charset = charset_desc(s)

    candidates = []

    # Rule-based detection first
    for rule in RULES:
        if rule["regex"].fullmatch(s):
            candidates.append({
                "name": rule["name"],
                "category": rule["category"],
                "confidence": rule["confidence"],
                "evidence": rule["evidence"],
                "notes": rule.get("notes", []),
                "length": length,
                "charset": charset,
                "entropy": ent,
            })

    # Heuristic digest candidates
    candidates.extend(heuristic_candidates(s))

    if not candidates:
        candidates.append({
            "name": "Unknown / Unrecognized format",
            "category": "Unknown",
            "confidence": 0.20,
            "evidence": "No common signature matched",
            "notes": [
                "Might be custom/salted format or truncated digest.",
                "If you know the source (Linux shadow, DB, app framework), identification becomes easier."
            ],
            "length": length,
            "charset": charset,
            "entropy": ent,
        })

    # Deduplicate best by (name, category)
    best = {}
    for cand in candidates:
        key = (cand["name"], cand["category"])
        if key not in best or cand["confidence"] > best[key]["confidence"]:
            best[key] = cand

    candidates = sorted(best.values(), key=lambda x: x["confidence"], reverse=True)

    top = candidates[0]
    return {
        "input": user_input,
        "masked": mask_hash(user_input),
        "length": length,
        "charset": charset,
        "entropy": ent,
        "top": top,
        "candidates": candidates[:12],  # keep output clean
    }


# -----------------------------
# UI: banner + examples
# -----------------------------
EXAMPLES = [
    ("md5", "5f4dcc3b5aa765d61d8327deb882cf99"),
    ("sha1", "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"),
    ("sha224", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
    ("sha256", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"),
    ("sha384", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
    ("sha512", "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"),
    ("sha3_256", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    ("sha3_512", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
    ("blake2s", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
    ("blake2b", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
]


def print_banner():
    clear()
    title = pyfiglet.figlet_format(APP_NAME, font="slant")
    print(c(title, Fore.MAGENTA))

    print(c("┌" + "─" * 76 + "┐", Fore.CYAN))
    print(c("│ ", Fore.CYAN) + c(f"Made by {MADE_BY}".center(74), Fore.WHITE) + c(" │", Fore.CYAN))
    print(c("│ ", Fore.CYAN) + c("CLI Hash Type Detection • For Research & Forensics".center(74), Fore.WHITE) + c(" │", Fore.CYAN))
    print(c("└" + "─" * 76 + "┘", Fore.CYAN))

    print(hr(78, "─", Fore.BLUE))
    print(c("Examples (copy/paste to test):", Fore.YELLOW))
    for name, ex in EXAMPLES:
        print(f"  {c('•', Fore.CYAN)} {c(name.ljust(10), Fore.WHITE)}  {c(ex, Fore.GREEN, bright=False)}")
    print(hr(78, "─", Fore.BLUE))
    print(c("Paste your hash below (or type 'exit'):", Fore.WHITE))


# -----------------------------
# Pretty, readable output
# -----------------------------
def render_report(report: dict) -> str:
    top = report["top"]
    top_conf = int(round(top["confidence"] * 100))
    top_color = confidence_color(top["confidence"])

    lines = []
    lines.append(hr(78, "═", Fore.MAGENTA))
    lines.append(c("ANALYSIS SUMMARY", Fore.MAGENTA))
    lines.append(hr(78, "═", Fore.MAGENTA))

    lines.append(pad_kv("Input", report["masked"]))
    lines.append(pad_kv("Length", report["length"]))
    lines.append(pad_kv("Charset", report["charset"]))
    lines.append(pad_kv("Entropy", f"{report['entropy']:.2f} bits/char"))
    lines.append(hr(78, "─", Fore.BLUE))

    lines.append(c("TOP MATCH", Fore.YELLOW))
    lines.append(
        f"  {badge('TYPE', Fore.CYAN)} {c(top['name'], Fore.WHITE)}   "
        f"{badge('CONF', Fore.CYAN)} {c(str(top_conf)+'%', top_color)}   "
        f"{badge('CAT', Fore.CYAN)} {c(top['category'], Fore.WHITE)}"
    )
    lines.append(f"  {badge('EVIDENCE', Fore.CYAN)} {c(top['evidence'], Fore.WHITE, bright=False)}")
    if top.get("notes"):
        for n in top["notes"]:
            lines.append(f"  {badge('NOTE', Fore.CYAN)} {c(n, Fore.WHITE, bright=False)}")

    lines.append(hr(78, "─", Fore.BLUE))
    lines.append(c("OTHER POSSIBLE TYPES", Fore.YELLOW))
    for i, cand in enumerate(report["candidates"], start=1):
        conf_pct = int(round(cand["confidence"] * 100))
        conf_col = confidence_color(cand["confidence"])
        lines.append(
            f"  {c(str(i).rjust(2)+'.', Fore.CYAN)} "
            f"{c(cand['name'], Fore.WHITE)} "
            f"{c('•', Fore.BLUE)} {c(cand['category'], Fore.WHITE, bright=False)} "
            f"{c('•', Fore.BLUE)} {c(str(conf_pct)+'%', conf_col)}"
        )
        lines.append(f"      {c('↳', Fore.CYAN)} {c(cand['evidence'], Fore.WHITE, bright=False)}")
    lines.append(hr(78, "═", Fore.MAGENTA))
    return "\n".join(lines)


def render_report_plain(report: dict) -> str:
    top = report["top"]
    lines = []
    lines.append("HASH IDENTIFIER REPORT - Cyber Bro's")
    lines.append("=" * 78)
    lines.append("ANALYSIS SUMMARY")
    lines.append("-" * 78)
    lines.append(f"Input (masked): {report['masked']}")
    lines.append(f"Length       : {report['length']}")
    lines.append(f"Charset      : {report['charset']}")
    lines.append(f"Entropy      : {report['entropy']:.2f} bits/char")
    lines.append("-" * 78)
    lines.append("TOP MATCH")
    lines.append(f"Type        : {top['name']}")
    lines.append(f"Confidence  : {int(round(top['confidence']*100))}%")
    lines.append(f"Category    : {top['category']}")
    lines.append(f"Evidence    : {top['evidence']}")
    if top.get("notes"):
        for n in top["notes"]:
            lines.append(f"Note        : {n}")
    lines.append("-" * 78)
    lines.append("OTHER POSSIBLE TYPES")
    for i, cand in enumerate(report["candidates"], start=1):
        lines.append(
            f"{str(i).rjust(2)}. {cand['name']}  |  {cand['category']}  |  {int(round(cand['confidence']*100))}%"
        )
        lines.append(f"    -> {cand['evidence']}")
    lines.append("=" * 78)
    return "\n".join(lines)


def save_report_to_file(report_plain: str, original_input: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", original_input.strip())[:28] or "hash"
    filename = f"hash_report_{safe}_{ts}.txt"
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(report_plain)
        f.write("\n")
    return path


# -----------------------------
# Main
# -----------------------------
def main():
    while True:
        print_banner()
        user_in = input(c("Hash > ", Fore.GREEN)).strip()

        if not user_in:
            print(c("No input provided. Try again.", Fore.RED))
            time.sleep(0.9)
            continue

        if user_in.lower() in ("exit", "quit", "q"):
            print(c("\nGoodbye 👋", Fore.CYAN))
            break

        hacker_loading("Analyzing hash", seconds=1.5)

        report = classify_hash(user_in)
        print(render_report(report))

        print(c("Save report to .txt (same folder as script)?", Fore.YELLOW))
        choice = input(c("[Y]es / [N]o > ", Fore.GREEN)).strip().lower()

        if choice in ("y", "yes"):
            try:
                path = save_report_to_file(render_report_plain(report), user_in)
                print(c(f"Saved: {path}", Fore.GREEN))
            except Exception as e:
                print(c(f"Failed to save file: {e}", Fore.RED))
        else:
            print(c("Not saved.", Fore.CYAN))

        input(c("\nPress Enter to continue...", Fore.WHITE))


if __name__ == "__main__":
    main()

"""
WordForge — bundled base wordlists + loader for downloaded public lists.

`COMMON_PASSWORDS` / `WIFI_COMMON` are small, offline samples of the *public*
common-password research corpora (the kind published in SecLists / rockyou and
every "worst passwords of the year" list). They contain NO personal data and no
breach combolists — just the generic weak passwords everyone already knows.

They serve two jobs:
  1. training material for the built-in Markov model (localmodel.py), and
  2. the "generic fill" that makes up the bulk of a generated wordlist.

`load_file()` lets the app fold in a larger list the user downloaded from the
Browse tab (e.g. rockyou.txt, SecLists Top-1M) to train on and blend from.
"""

from __future__ import annotations

import re

# Detects an email address so we can strip it out (PII, never a password).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DELIMS = re.compile(r"[:;|,\t]")

# Classic, widely-published weak passwords (public knowledge; not personal).
COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
    "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
    "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
    "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
    "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper",
    "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
    "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
    "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "mobilemail", "monitor", "monkeybone",
    "montana", "moon", "moscow", "welcome", "admin", "login", "passw0rd",
    "password1", "password123", "qwerty123", "1q2w3e4r", "1q2w3e", "zaq12wsx",
    "asdf1234", "qwe123", "changeme", "secret", "whatever", "flower", "hello",
    "test", "guest", "root", "toor", "letmein1", "iloveyou1", "monkey1",
    "dragon1", "abcd1234", "a1b2c3d4", "passpass", "internet", "samsung",
    "google", "facebook", "amazon", "spider", "orange", "purple", "silver",
    "golden", "diamond", "crystal", "phoenix", "eagle", "falcon", "tiger",
    "lion", "panther", "warrior", "legend", "ninja", "samurai", "viking",
    "cowboys", "lakers", "chelsea", "arsenal", "liverpool", "barcelona",
    "chocolate", "cookie", "coffee", "guitar", "rocket", "galaxy", "cosmos",
    "captain", "hunter2", "trustno1!", "welcome1", "welcome123", "admin123",
    "root123", "test123", "pass123", "love123", "summer2023", "winter2023",
    "spring2024", "autumn2024", "january1", "december1", "qwerty1", "asdfghjkl",
    "1qazxsw2", "poiuytrewq", "mnbvcxz", "0987654321", "qwertyui", "zxcasdqwe",
    "ncc1701", "aa123456", "1234qwer", "q1w2e3r4", "1234abcd", "passw0rd1",
]

# Common WPA/WPA2 passphrases (>= 8 chars, network-flavored). Public/generic.
WIFI_COMMON = [
    "12345678", "password", "internet", "wireless", "qwertyuiop", "abcd1234",
    "password1", "password123", "administrator", "changeme1", "letmein123",
    "welcome123", "1234567890", "computer1", "wifipassword", "homewifi123",
    "mypassword", "guestwifi", "network123", "router123", "admin1234",
    "iloveyou123", "sunshine1", "football1", "baseball1", "dragon123",
    "monkey123", "shadow123", "master123", "superman1", "starwars1",
    "qwerty1234", "0000000000", "1111111111", "1qaz2wsx3edc", "zaq1zaq1",
    "trustno1234", "family123", "welcome2023", "internet123", "connectme1",
]


def base_words(profile: str) -> list[str]:
    """Base pool for a profile (WPA needs 8..63; accounts need >=6)."""
    if profile == "wifi":
        pool = WIFI_COMMON + [w for w in COMMON_PASSWORDS if len(w) >= 8]
        return [w for w in pool if 8 <= len(w) <= 63]
    return list(COMMON_PASSWORDS)


def password_only(line: str) -> str | None:
    """Reduce one wordlist/combolist line to just its PASSWORD, dropping any PII.

    Standard public password lists (rockyou, SecLists) are already password-only,
    so those pass straight through. But if a line is a raw breach combolist entry
    like ``email:password`` / ``user:pass:pass`` / ``email;pass``, we keep only
    the last field (the password) and discard the identifying columns. Any line
    that is itself an email address is dropped entirely. Nothing that looks like
    PII ever reaches the wordlist or the model.
    """
    s = line.rstrip("\r\n").strip()
    if not s:
        return None
    if _DELIMS.search(s):
        # last field is the password in email:pass / user:pass[:pass] formats
        s = _DELIMS.split(s)[-1].strip()
    if not s or _EMAIL_RE.match(s):
        return None            # a bare email address -> drop (PII)
    if len(s) > 64:            # not a realistic password
        return None
    return s                   # keeps leet passwords like p@ssw0rd


def load_file(path: str, max_lines: int = 200000) -> list[str]:
    """Read a wordlist as PASSWORDS ONLY. PII (emails/usernames) is stripped —
    if the file is a breach combolist, only the password column survives."""
    out: list[str] = []
    seen: set[str] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            pw = password_only(line)
            if pw and pw not in seen:
                seen.add(pw)
                out.append(pw)
            if len(out) >= max_lines:
                break
    return out

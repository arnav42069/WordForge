"""
WordForge — public wordlist catalog + downloader.

This deliberately catalogs REPUTABLE, LEGALLY-DISTRIBUTED, PUBLIC wordlist
collections — the same ones that ship with Kali Linux and are the standard for
authorized security testing. It does NOT crawl for, index, or download fresh
"leaked" breach dumps (email:password combolists), which are stolen personal
data belonging to real third parties.

Each entry links to an upstream project page and a direct download URL that the
project itself publishes.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from dataclasses import dataclass

# Local cache for downloaded lists + a manifest used for update checks.
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".wordforge", "wordlists")
MANIFEST = os.path.join(CACHE_DIR, "manifest.json")

# Lists auto-fetched on launch so generation always has a real base to append to.
DEFAULT_BASE_NAME = "SecLists — Top 10k Passwords"          # email/account mode
DEFAULT_WIFI_BASE_NAME = "SecLists — WiFi / WPA (Common)"   # wifi mode


@dataclass
class WordlistInfo:
    name: str
    category: str
    approx_size: str
    published: str          # upstream release / last-updated indicator
    description: str
    project_url: str
    download_url: str


# Sorted newest-ish first so the "browse by date" view is meaningful.
CATALOG: list[WordlistInfo] = [
    WordlistInfo(
        name="SecLists (full)",
        category="general / everything",
        approx_size="~1.2 GB",
        published="2025 (rolling)",
        description="The security tester's companion. Usernames, passwords, "
                    "fuzzing payloads, web content, and more. Actively maintained.",
        project_url="https://github.com/danielmiessler/SecLists",
        download_url="https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip",
    ),
    WordlistInfo(
        name="SecLists — Common Passwords (Top 1M)",
        category="passwords",
        approx_size="~8 MB",
        published="2025 (rolling)",
        description="Xato / Mark Burnett top 1,000,000 most common passwords. "
                    "Great default for account-password audits.",
        project_url="https://github.com/danielmiessler/SecLists/tree/master/Passwords",
        download_url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-1000000.txt",
    ),
    WordlistInfo(
        name="SecLists — Top 10k Passwords",
        category="passwords",
        approx_size="~80 KB",
        published="2025 (rolling)",
        description="Fast, high-hit-rate short list for quick account audits.",
        project_url="https://github.com/danielmiessler/SecLists/tree/master/Passwords",
        download_url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    ),
    WordlistInfo(
        name="SecLists — WiFi / WPA (Common)",
        category="wifi",
        approx_size="~1 MB",
        published="2025 (rolling)",
        description="Common WPA/WPA2 passphrases (>=8 chars) for authorized "
                    "wireless assessments.",
        project_url="https://github.com/danielmiessler/SecLists/tree/master/Passwords/WiFi-WPA",
        download_url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
    ),
    WordlistInfo(
        name="rockyou.txt",
        category="passwords",
        approx_size="~133 MB",
        published="classic (2009 leak, now public research corpus)",
        description="The canonical password-audit wordlist. ~14M entries. "
                    "Bundled with Kali; hosted here via SecLists mirror.",
        project_url="https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases",
        download_url="https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz",
    ),
    WordlistInfo(
        name="Probable-Wordlists (Top Passwords)",
        category="passwords",
        approx_size="~15 MB",
        published="2024",
        description="Berzerk0's research-ranked 'most probable' password lists, "
                    "ordered by real-world frequency.",
        project_url="https://github.com/berzerk0/Probable-Wordlists",
        download_url="https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt",
    ),
    WordlistInfo(
        name="Weakpass — reference page",
        category="passwords / wifi",
        approx_size="varies (up to tens of GB)",
        published="rolling",
        description="Aggregated, curated public cracking dictionaries with sizes "
                    "and hit-rate stats. Opens the project site to pick a list.",
        project_url="https://weakpass.com/wordlist",
        download_url="https://weakpass.com/wordlist",
    ),
    WordlistInfo(
        name="CrackStation dictionary — reference page",
        category="passwords",
        approx_size="~15 GB (human) / ~247 GB (full)",
        published="rolling",
        description="Large public cracking dictionary. Opens the project page "
                    "(direct link is torrent/HTTP from the vendor).",
        project_url="https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm",
        download_url="https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm",
    ),
]


def categories() -> list[str]:
    return ["all"] + sorted({w.category for w in CATALOG})


def filter_catalog(query: str = "", category: str = "all") -> list[WordlistInfo]:
    q = (query or "").lower().strip()
    out = []
    for w in CATALOG:
        if category != "all" and w.category != category:
            continue
        if q and q not in w.name.lower() and q not in w.description.lower() \
                and q not in w.category.lower():
            continue
        out.append(w)
    return out


def download(info: WordlistInfo, dest_dir: str, progress=None) -> str:
    """Download a catalog entry to dest_dir. Returns the saved path.

    For 'reference page' entries the download_url is an HTML page; we still save
    it (or the caller can just open it in a browser instead).
    """
    os.makedirs(dest_dir, exist_ok=True)
    fname = info.download_url.rstrip("/").split("/")[-1] or "wordlist"
    if "." not in fname:
        fname += ".html"
    dest = os.path.join(dest_dir, fname)

    req = urllib.request.Request(
        info.download_url, headers={"User-Agent": "WordForge/1.0 (+authorized-testing)"}
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        total = int(r.headers.get("Content-Length", 0))
        read = 0
        chunk = 1024 * 256
        with open(dest, "wb") as f:
            while True:
                buf = r.read(chunk)
                if not buf:
                    break
                f.write(buf)
                read += len(buf)
                if progress:
                    if total:
                        progress(f"{read // 1024} / {total // 1024} KB "
                                 f"({read * 100 // total}%)")
                    else:
                        progress(f"{read // 1024} KB")
    return dest


# --------------------------------------------------------------------------- #
# Update checks + local cache (reputable public sources only — no breach data)
# --------------------------------------------------------------------------- #

def is_reference(info: WordlistInfo) -> bool:
    u = info.download_url
    return (u.endswith((".htm", ".html", "/wordlist"))
            or "weakpass" in u or "crackstation" in u)


def _load_manifest() -> dict:
    try:
        with open(MANIFEST, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


def _save_manifest(d: dict) -> None:
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(MANIFEST, "w", encoding="utf-8") as f:
            json.dump(d, f)
    except Exception:  # noqa: BLE001
        pass


def cache_path(info: WordlistInfo) -> str:
    fname = info.download_url.rstrip("/").split("/")[-1] or "wordlist"
    return os.path.join(CACHE_DIR, fname)


def _head(url: str, timeout: int = 8) -> dict:
    """Lightweight freshness probe of a public list's upstream URL."""
    try:
        req = urllib.request.Request(
            url, method="HEAD",
            headers={"User-Agent": "WordForge/1.0 (+authorized-testing)"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"size": r.headers.get("Content-Length", ""),
                    "etag": r.headers.get("ETag", ""),
                    "modified": r.headers.get("Last-Modified", "")}
    except Exception:  # noqa: BLE001
        return {}


def check_updates(progress=None) -> dict[str, str]:
    """Probe the curated public wordlists for changes since last launch.

    Returns {name: status} where status is one of:
    new / updated / current / reference / unknown. Only reputable, legally
    distributed lists are tracked — breach combolists are never fetched.
    """
    manifest = _load_manifest()
    result: dict[str, str] = {}
    for w in CATALOG:
        if progress:
            progress(f"Checking {w.name}…")
        if is_reference(w):
            result[w.name] = "reference"
            continue
        hi = _head(w.download_url)
        sig = hi.get("etag") or hi.get("modified") or hi.get("size")
        if not sig:
            result[w.name] = "unknown"
            continue
        prev = manifest.get(w.name)
        if prev is None:
            result[w.name] = "new"
        elif prev.get("sig") != sig:
            result[w.name] = "updated"
        else:
            result[w.name] = "current"
        manifest[w.name] = {"sig": sig, "checked": time.time()}
    _save_manifest(manifest)
    return result


def by_name(name: str):
    for w in CATALOG:
        if w.name == name:
            return w
    return None


def ensure_base(name: str, progress=None) -> str | None:
    """Make sure a named base list exists locally (auto-fetch on first launch).
    Returns a local path, or None if unavailable (e.g. offline)."""
    info = by_name(name)
    if info is None:
        return None
    dest = cache_path(info)
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return dest
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        return download(info, CACHE_DIR, progress=progress)
    except Exception:  # noqa: BLE001
        return None


def ensure_default_base(progress=None) -> str | None:
    return ensure_base(DEFAULT_BASE_NAME, progress=progress)

# WordForge

Context-aware wordlist builder for **authorized** security testing (pentests,
red-team engagements, CTFs, and defensive password auditing). Cross-platform
(Linux + Windows), Tkinter GUI, optional local LLM via Ollama.

> ⚠ **Use only against systems you own or have explicit written permission to
> test.** WordForge only *generates candidate strings and downloads public
> dictionaries*; it never connects to, authenticates against, or attacks a
> target. What you do with the output is your legal responsibility.

## Modes

- **WiFi Wordlist** — WPA/WPA2 passphrase candidates (8–63 chars). The only
  required field is the **Network SSID**; everything else is optional. The SSID
  is mutated richly (name + digits / every year / specials / PINs), which is the
  most productive source when you know the network. WiFi mode appends onto a real
  **WPA wordlist** fetched from the Browse tab.
- **Email Wordlist** — account-password candidates (6–64 chars) from names, pet,
  company, hobbies, dates. Appends onto a real **passwords wordlist**.
- **Browse** — search/download **reputable, legally-distributed** public
  wordlists (SecLists, rockyou, Probable-Wordlists, Weakpass, CrackStation).
  Auto-checks these for new/updated versions on launch (status column).

### Length & base
Set **Length (records)** to the exact size you want (default **250,000**). The
list is your targeted candidates on top, then the **entire selected base
wordlist appended in full**, then numeric/model fill up to the requested length —
so nothing in the base is dropped. Each mode shows its base ("Builds on: …") with
a **Change base…** button to point at a bigger list you downloaded from Browse.

### Note on "leaked" lists
WordForge intentionally does **not** crawl for or auto-download freshly leaked
breach dumps (email:password combolists). Those are stolen personal data about
real people and fuel credential-stuffing; distributing them causes third-party
harm. The Browse tab instead surfaces the standard public research corpora that
ship with Kali and are appropriate for authorized work.

## How generation works
1. **Built-in local model** (always on, ships in the exe): a from-scratch
   character-level **Markov password model** (`localmodel.py`) trained at startup
   on an embedded corpus of generic weak-password patterns. It emits novel
   password-like samples and "completes" your context tokens with realistic
   learned tails (e.g. `bella` → `bella2021`, `bella!@#`). No network, no Ollama,
   no download — WordForge always has a working local model.
2. **Rule engine** (always on): CUPP/CeWL-style token mutation — case variants,
   leetspeak, common prefixes/suffixes, year/number appending, keyword pairing.
3. **Ollama** (optional upgrade): if [Ollama](https://ollama.com) is running on
   `localhost:11434`, pick one of its models from the **Model** dropdown and its
   output is blended in on top of the built-in model.

The **Model** dropdown always lists the built-in model first. Click **Detect
Ollama models** to add any local Ollama models. To set Ollama up:
```bash
ollama pull llama3        # or mistral, qwen2, etc.
```

### Email mode note
Email mode never builds passwords out of the target's email address — people
don't put their own address in their email password. It uses the *other*
personal context (names, pet, dates, hobbies) plus the built-in model's learned
common-password patterns.

### List composition & base wordlist
A generated list is deliberately mixed so target keywords don't drown out broad
coverage:
1. **personalized** model completions of the target's context (on top, so the
   likely guesses are tried first),
2. **capped keyword mutations** — at most ~30% of the list,
3. the **bulk (≥60%)**: the chosen **base wordlist** interleaved with novel
   model samples.

The **Base wordlist** bar shows what the list is building on. It defaults to a
bundled offline sample of the standard public common-password lists. Click
**Use downloaded list…** to point it at a bigger list you fetched from the
**Browse** tab (e.g. rockyou.txt, SecLists Top-1M) — WordForge will both blend
from it *and retrain the built-in model on it*, so samples match real-world
password shapes and hit-rate goes up. The base name is shown on the Generate
tabs.

### Real data, no PII
The realistic passwords come from the **public, legally-distributed research
corpora** (rockyou, SecLists, Probable-Wordlists) — these *are* the password
columns of real breaches with all emails/usernames already removed, which is the
standard, legal way to use breach-derived data.

Two safeguards keep PII out no matter what you load:
* **`load_file` is passwords-only.** Any list you point it at is reduced to the
  password field. If a line is a raw combolist entry (`email:password`,
  `user:pass:pass`), only the password survives; a bare email address is dropped.
* **The generator never emits an email.** A final filter drops any candidate
  that is an email address (leet passwords like `p@ssw0rd` are kept — only true
  `name@domain.tld` PII is removed).

### Launch update
Every time WordForge opens it (a) auto-fetches the small default base list if
missing so generation always extends a real wordlist, and (b) HEAD-probes the
tracked public leaked-password wordlists for **new/updated** versions, flagged in
the Browse tab's *status* column. It does **not** crawl for or download raw
breach dumps — sourcing fresh stolen combolists harms the third parties in them,
independent of any authorization to test one target.

### Numeric-heavy candidates
~25–30% of a list is mostly-numeric (a digit run with a 1–4 char cluster at the
start/middle/end, plus PIN/phone/date-style pure numerics seeded from the
target's numbers/years) — a very common real pattern, especially for WPA keys.

## Installation

WordForge has **no third-party runtime dependencies** — it runs on the Python
standard library (Tkinter). You need **Python 3.10+**. PyInstaller is only
needed if you want to (re)build a standalone executable.

### Windows

The fastest path is the prebuilt one-file executable — no Python required:

1. Grab `dist/WordForge.exe` from the repo (or build it, below).
2. Double-click it. That's it — the exe bundles Python and Tkinter.

To run from source instead:

```powershell
# Install Python 3.10+ from https://python.org (tick "Add python.exe to PATH").
# Tkinter is included in the official Windows installer.
git clone https://github.com/arnav42069/WordForge.git
cd WordForge
python app.py
```

Build the exe yourself:

```powershell
pip install pyinstaller
pyinstaller --onefile --windowed --name WordForge app.py
# result: dist\WordForge.exe
```

### Linux

Tkinter is **not** bundled with Python on most distros — install it first:

```bash
# Debian / Ubuntu / Kali / Mint
sudo apt update && sudo apt install -y python3 python3-tk

# Fedora / RHEL
sudo dnf install -y python3 python3-tkinter

# Arch / Manjaro
sudo pacman -S python tk
```

Then run from source:

```bash
git clone https://github.com/arnav42069/WordForge.git
cd WordForge
python3 app.py
```

Optionally build a standalone Linux binary (produces `dist/WordForge`):

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name WordForge app.py
./dist/WordForge
```

> The one-file exe/binary is platform-specific: build it on the OS you intend
> to run it on (a Windows `.exe` won't run on Linux and vice-versa).

## Files
| file | purpose |
|------|---------|
| `app.py` | Tkinter GUI (WiFi / Email / Browse tabs) |
| `engine.py` | rule engine + Ollama client + orchestration |
| `catalog.py` | curated public-wordlist catalog + downloader |

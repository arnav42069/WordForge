"""
WordForge — generation engine.

Context-aware password-candidate wordlist generation for AUTHORIZED security
testing (penetration tests, red-team engagements, CTFs, and defensive password
auditing). Two profiles:

  * wifi  -> WPA/WPA2 candidates (enforces 8..63 char PSK length rules)
  * email -> account-password candidates (common human password patterns)

The engine has two cooperating parts:
  1. A deterministic rule engine (CUPP/CeWL-style token mutation).
  2. An optional local LLM (Ollama, http://localhost:11434) that expands the
     target context into extra plausible candidates. If Ollama is not running,
     the rule engine is used alone.

Nothing here talks to a target, cracks anything, or exfiltrates data. It only
produces candidate strings to a local file, which is what a wordlist tool does.
"""

from __future__ import annotations

import datetime
import itertools
import json
import random
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field

import localmodel
import baselist
import pcfg

OLLAMA_URL = "http://localhost:11434"

# "Current" year window, used for corporate/seasonal defaults and blends.
CUR_YEAR = datetime.date.today().year

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

LEET_MAP = {
    "a": ["a", "@", "4"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "$", "5"],
    "t": ["t", "7"],
    "b": ["b", "8"],
    "g": ["g", "9"],
}

COMMON_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456", "!", "!!", "@", "#", "$",
    "01", "007", "69", "99", "00", "111", "321", "2020", "2021", "2022",
    "2023", "2024", "2025", "!@#", "123!", "1!",
]

COMMON_PREFIXES = ["", "!", "@", "#"]

WIFI_MIN, WIFI_MAX = 8, 63


@dataclass
class Target:
    """Free-form target context supplied by the (authorized) tester."""
    ssid: str = ""                                     # Wi-Fi network name (wifi mode)
    keywords: list[str] = field(default_factory=list)  # names, pet, company... (optional)
    years: list[str] = field(default_factory=list)     # birth years, founding years...
    numbers: list[str] = field(default_factory=list)   # phone fragments, house no., pin...
    notes: str = ""                                     # free text handed to the LLM

    @staticmethod
    def _split(raw: str) -> list[str]:
        parts = re.split(r"[,\n;]+", raw or "")
        return [p.strip() for p in parts if p.strip()]

    @classmethod
    def from_fields(cls, keywords: str, years: str, numbers: str, notes: str,
                    ssid: str = "") -> "Target":
        return cls(
            ssid=(ssid or "").strip(),
            keywords=cls._split(keywords),
            years=cls._split(years),
            numbers=cls._split(numbers),
            notes=(notes or "").strip(),
        )


# --------------------------------------------------------------------------- #
# Rule engine
# --------------------------------------------------------------------------- #

def _case_variants(word: str) -> set[str]:
    out = {word, word.lower(), word.upper(), word.capitalize()}
    if len(word) > 1:
        out.add(word[0].upper() + word[1:].lower())
    return out


def _leet_variants(word: str, max_variants: int = 6) -> set[str]:
    lw = word.lower()
    choices = [LEET_MAP.get(ch, [ch]) for ch in lw]
    out: set[str] = set()
    for combo in itertools.product(*choices):
        out.add("".join(combo))
        if len(out) >= max_variants:
            break
    return out


# --- smart (human-like) leetspeak ----------------------------------------- #
# A single, common substitution per eligible position rather than the full
# combinatorial explosion — real people leet one or two letters, not all of
# them, so this avoids junk like "p455w0rd".
_SMART_LEET = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}


def smart_leet(word: str, max_variants: int = 4) -> set[str]:
    """Partial, capitalization-preserving leet: swap only the first eligible
    letter, only the last, or a leading-cap + one swap. Human, not exhaustive."""
    out: set[str] = set()
    idxs = [i for i, ch in enumerate(word) if ch.lower() in _SMART_LEET]
    if not idxs:
        return out
    for pos in (idxs[0], idxs[-1]):
        chars = list(word)
        chars[pos] = _SMART_LEET[chars[pos].lower()]
        out.add("".join(chars))
    # Capitalize first letter, leet the last eligible — a very common shape.
    chars = list(word.capitalize())
    chars[idxs[-1]] = _SMART_LEET[word[idxs[-1]].lower()]
    out.add("".join(chars))
    return set(list(out)[:max_variants])


# --- keyboard walks + adjacency ------------------------------------------- #
_QWERTY_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]

# map each key to the key one position to its right on the same row (wraps off
# the end -> unchanged), for "keyboard-shifted" mutations of a keyword.
_KEY_RIGHT: dict[str, str] = {}
for _row in _QWERTY_ROWS:
    for _i, _c in enumerate(_row[:-1]):
        _KEY_RIGHT[_c] = _row[_i + 1]
        _KEY_RIGHT[_c.upper()] = _row[_i + 1].upper()

# Common spatial patterns people actually pick as passwords.
KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "qwerty123", "qwertyui", "asdf", "asdfgh",
    "asdfghjkl", "zxcvbn", "zxcvbnm", "zxcvbnm123", "1qaz", "2wsx", "3edc",
    "1qaz2wsx", "1qaz2wsx3edc", "qazwsx", "qazwsxedc", "1q2w3e", "1q2w3e4r",
    "1q2w3e4r5t", "qweasd", "qweasdzxc", "qazxsw", "poiuy", "poiuytrewq",
    "mnbvcxz", "lkjhgf", "0okm", "9ijn", "zaq1", "zaq12wsx",
]


def keyboard_shift(word: str) -> str:
    """Shift every key one position right on QWERTY (bella -> nq;;s style)."""
    return "".join(_KEY_RIGHT.get(ch, ch) for ch in word)


def keyboard_walk_candidates(t: Target) -> list[str]:
    out: list[str] = list(KEYBOARD_WALKS)
    kws = list(t.keywords)
    if t.ssid:
        kws = [t.ssid] + kws
    for kw in kws:
        low = re.sub(r"\s+", "", kw.lower())
        if not low:
            continue
        sh = keyboard_shift(low)
        if sh and sh != low:
            out.append(sh)
    return list(dict.fromkeys(out))


# --- contextual token blending -------------------------------------------- #
def _clean_kw(t: Target, profile: str) -> list[str]:
    kws = list(t.keywords)
    if t.ssid:
        kws = [t.ssid] + kws
    out = []
    for kw in kws:
        if profile == "email" and (EMAIL_RE.match(kw) or "@" in kw):
            continue
        out.append(kw)
    return out


def blend_candidates(t: Target, profile: str, max_out: int = 4000) -> list[str]:
    """Permute keywords with years/numbers/specials into the highly-probable
    human templates: [Cap][Year], [Year][Cap], [Keyword][Special][Digit], …"""
    kws = _clean_kw(t, profile)
    years = list(t.years) + [str(CUR_YEAR), str(CUR_YEAR - 1)]
    years = list(dict.fromkeys(years))
    nums = list(t.numbers)
    specials = ["!", "@", "#", "$", "."]
    digits = ["1", "12", "123", "01", "007"]

    out: list[str] = []
    seen: set[str] = set()

    def emit(w: str) -> bool:
        if w and w not in seen:
            seen.add(w)
            out.append(w)
        return len(out) < max_out

    for kw in kws:
        cap = re.sub(r"\s+", "", kw).capitalize()
        low = re.sub(r"\s+", "", kw).lower()
        if not cap:
            continue
        for y in years:
            for w in (cap + y, y + cap, low + y, cap + "!" + y, cap + "@" + y):
                if not emit(w):
                    return out
        for n in nums:
            for w in (cap + n, n + cap, cap + "!" + n, low + n):
                if not emit(w):
                    return out
        for s in specials:
            for d in digits:
                if not emit(cap + s + d):
                    return out
            if not emit(cap + s):
                return out
    return out


# --- corporate & seasonal defaults (target-specific OSINT) ---------------- #
_SEASONS = ["Spring", "Summer", "Autumn", "Fall", "Winter"]
_CORP_WORDS = ["Welcome", "Password", "Passw0rd", "Changeme", "ChangeMe",
               "Admin", "Letmein", "Login", "Default", "Company", "Temp"]


def corporate_seasonal_candidates(t: Target, profile: str,
                                  base_year: int | None = None,
                                  max_out: int = 6000) -> list[str]:
    """Season/year + corporate-placeholder passwords (Spring2026, Winter26!,
    Welcome2025!, Company123) combined with the target's company token."""
    y = base_year or CUR_YEAR
    year_ints = [y, y + 1, y - 1, y - 2]
    yy = [str(v) for v in year_ints] + [str(v)[2:] for v in year_ints]
    yy = list(dict.fromkeys(yy))
    tails = ["", "!", "#", "1", "123", "!@#"]

    out: list[str] = []
    seen: set[str] = set()

    def emit(w: str) -> bool:
        if w and w not in seen:
            seen.add(w)
            out.append(w)
        return len(out) < max_out

    for season in _SEASONS:
        for ys in yy:
            for tl in ("", "!", "#"):
                if not emit(season + ys + tl):
                    return out
            if not emit(season.lower() + ys):
                return out
    for word in _CORP_WORDS:
        for ys in yy + [""]:
            for tl in tails:
                if not emit(word + ys + tl):
                    return out

    for comp in _clean_kw(t, profile):
        cc = re.sub(r"\s+", "", comp).capitalize()
        if not cc:
            continue
        for ys in yy + [""]:
            for w in (cc + ys, cc + "@" + ys, cc + ys + "!", cc + "123",
                      "Welcome" + cc, cc + "Admin"):
                if not emit(w):
                    return out
    return out


# --- PCFG-backed structural candidates ------------------------------------ #
def pcfg_seeded(t: Target, profile: str, n: int) -> list[str]:
    """Structure-aware personalized candidates: real password shapes filled
    with the target's own tokens (+ Markov terminals)."""
    if n <= 0:
        return []
    tokens = _base_tokens(t, profile)
    return pcfg.get_pcfg().generate(n, tokens=tokens, years=t.years,
                                    numbers=t.numbers)


def pcfg_free(n: int) -> list[str]:
    """Novel candidates drawn from the mined structure distribution."""
    if n <= 0:
        return []
    return pcfg.get_pcfg().generate(n)


def _base_tokens(t: Target, profile: str = "email") -> list[str]:
    tokens: set[str] = set()
    kws = list(t.keywords)
    if t.ssid:
        kws = [t.ssid] + kws                # SSID is the strongest wifi seed
    for kw in kws:
        # People don't put their email address inside their email password.
        # In email mode, drop full email addresses; keep the rest of the context.
        if profile == "email" and (EMAIL_RE.match(kw) or "@" in kw):
            continue
        tokens.update(_case_variants(kw))
        # split multi-word keywords too ("Acme Corp" -> Acme, Corp, AcmeCorp)
        pieces = re.split(r"\s+", kw)
        if len(pieces) > 1:
            tokens.add("".join(p.capitalize() for p in pieces))
            for p in pieces:
                tokens.update(_case_variants(p))
    return [tok for tok in tokens if tok]


def rule_candidates(t: Target, profile: str = "email", use_leet: bool = True,
                    max_out: int = 5000) -> list[str]:
    """Keyword-derived candidates (CUPP-style mutations of the target's own
    context). Intentionally CAPPED: these are the highest-signal guesses but a
    full combinatorial expansion drowns out everything else, so `max_out` keeps
    them a minority of the final list (see `generate`)."""
    bases = _base_tokens(t, profile)
    # Trim the affix set so we don't produce tens of thousands of near-dupes per
    # base. Years/numbers the tester supplied are high-signal, so keep those.
    affixes = ["", "1", "12", "123", "1234", "12345", "123456", "!", "@", "#",
               "$", "!!", "007", "69", "2024", "2025", "123!", "1!"]
    affixes += t.years + t.numbers
    # de-dupe affixes, keep order
    seen_aff: set[str] = set()
    affixes = [a for a in affixes if not (a in seen_aff or seen_aff.add(a))]

    seen: set[str] = set()
    out: list[str] = []

    def emit(word: str) -> bool:
        if not word or word in seen:
            return True
        seen.add(word)
        out.append(word)
        return len(out) < max_out

    for base in bases:
        variants = {base}
        if use_leet:
            # human-like partial leet first; a couple of exhaustive ones too
            variants |= smart_leet(base, max_variants=4)
            variants |= _leet_variants(base, max_variants=2)
        for v in variants:
            for pre in ("", "!", "@"):
                for suf in affixes:
                    if not emit(pre + v + suf):
                        return out
    return out


# --------------------------------------------------------------------------- #
# WPA / email post-filters
# --------------------------------------------------------------------------- #

def _is_pii(w: str) -> bool:
    """Defensive: a candidate must never be an email/username-with-@ (PII)."""
    return "@" in w and EMAIL_RE.match(w) is not None


def apply_profile(words: list[str], profile: str) -> list[str]:
    if profile == "wifi":
        return [w for w in words if WIFI_MIN <= len(w) <= WIFI_MAX and not _is_pii(w)]
    # email/account: most sites require >=6 (often >=8); keep 6..64
    return [w for w in words if 6 <= len(w) <= 64 and not _is_pii(w)]


# --------------------------------------------------------------------------- #
# Local LLM (Ollama) integration — optional
# --------------------------------------------------------------------------- #

def ollama_status() -> tuple[bool, list[str]]:
    """Return (running, [model names])."""
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode("utf-8"))
        return True, [m["name"] for m in data.get("models", [])]
    except Exception:
        return False, []


# Psychology-optimized auditor prompt. {context} / {count} are filled per call.
_LLM_SYSTEM_TMPL = (
    "Act as an authorized password security auditor. Given the following target "
    "context: {context}, generate {count} highly realistic password variations "
    "that a human would actually create. Mimic common human patterns, structural "
    "variations, and subtle typos. Output raw strings only, one per line. Do not "
    "include any conversational text, explanations, or numbering."
)


def _context_tokens(t: Target) -> str:
    bits: list[str] = []
    if t.ssid:
        bits.append(f"network SSID '{t.ssid}'")
    if t.keywords:
        bits.append("keywords " + ", ".join(t.keywords))
    if t.years:
        bits.append("years/dates " + ", ".join(t.years))
    if t.numbers:
        bits.append("numbers " + ", ".join(t.numbers))
    if t.notes:
        bits.append("notes: " + t.notes)
    return "; ".join(bits) if bits else "no specific context"


def ollama_candidates(t: Target, model: str, profile: str, want: int = 300,
                      timeout: int = 120) -> list[str]:
    system = _LLM_SYSTEM_TMPL.format(context=_context_tokens(t), count=want)
    constraint = ("Constraint: these are Wi-Fi WPA2 passphrases, 8-63 characters."
                  if profile == "wifi" else
                  "Constraint: these are website/account passwords, usually 6-16 "
                  "characters.")
    prompt = f"{constraint}\nOutput {want} candidate passwords now, one per line."
    payload = {
        "model": model,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {"temperature": 0.9, "top_p": 0.95},
    }
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    text = data.get("response", "")
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip().strip("`").strip()
        s = re.sub(r"^\s*[\d]+[\.\)]\s*", "", s)   # strip "1. " / "2) "
        s = re.sub(r"^[-*]\s*", "", s)             # strip bullets
        if s and " " not in s.strip() or (profile == "wifi"):
            # wifi passphrases may contain spaces; account pw usually not
            if s:
                out.append(s)
    return out


# --------------------------------------------------------------------------- #
# Built-in local model (always available, ships with the app)
# --------------------------------------------------------------------------- #

def builtin_seeded(t: Target, profile: str, per_token: int = 5) -> list[str]:
    """Personalized: complete the target's own context tokens with realistic
    learned tails (e.g. bella -> bella2021, bella!@#)."""
    seeds = _base_tokens(t, profile)
    return localmodel.generate(seed_tokens=seeds, n_free=0, n_seeded=per_token)


def builtin_free(n: int) -> list[str]:
    """Generic novel passwords sampled from the learned distribution — the
    'more random, distantly-connected' bulk of the list."""
    if n <= 0:
        return []
    return localmodel.generate(seed_tokens=None, n_free=n, n_seeded=0)


# Short non-digit clusters to embed inside numeric-heavy candidates.
_NUM_CLUSTERS = ["a", "x", "q", "z", "k", "s", "pw", "ab", "xy", "qq", "abc",
                 "abcd", "pass", "key", "wifi", "net", "007", "pw1"]


def _digits(n: int) -> str:
    return "".join(random.choice("0123456789") for _ in range(max(0, n)))


def numeric_heavy_candidates(t: Target, profile: str, n: int) -> list[str]:
    """Mostly-numeric candidates: a run of digits with a small 1-4 char cluster
    at the start, middle, or end — plus PIN/phone/date-style pure numerics.
    A very common real-world pattern (and typical of WPA keys)."""
    if n <= 0:
        return []
    clusters = set(_NUM_CLUSTERS)
    for tok in _base_tokens(t, profile):
        low = re.sub(r"[^a-z0-9]", "", tok.lower())
        for k in (1, 2, 3, 4):
            if len(low) >= k:
                clusters.add(low[:k])
    clusters = [c for c in clusters if 1 <= len(c) <= 4]
    seeds = [re.sub(r"\D", "", x) for x in (t.numbers + t.years)]
    seeds = [s for s in seeds if s]

    lo = 8 if profile == "wifi" else 6
    hi = 63 if profile == "wifi" else 64
    out: list[str] = []
    seen: set[str] = set()

    def add(w: str) -> None:
        if w and w not in seen and lo <= len(w) <= hi:
            seen.add(w)
            out.append(w)

    tries = 0
    while len(out) < n and tries < n * 20 + 1000:
        tries += 1
        total = random.choice([8, 8, 9, 10, 10, 11, 12, 6 if profile != "wifi" else 8])
        # ~35% pure numeric (PIN/phone/date-like), rest digits + small cluster
        if random.random() < 0.35 or not clusters:
            if seeds and random.random() < 0.5:
                s = random.choice(seeds)
                w = (s + _digits(total - len(s)))[:total] if len(s) < total else s[:total]
            else:
                w = _digits(total)
            add(w)
            continue
        c = random.choice(clusters)
        digits = _digits(max(1, total - len(c)))
        where = random.choice(("start", "end", "mid"))
        if where == "start":
            add(c + digits)
        elif where == "end":
            add(digits + c)
        else:
            k = random.randint(1, max(1, len(digits) - 1))
            add(digits[:k] + c + digits[k:])
    return out


def _ssid_initials(t: Target) -> list[str]:
    """Initials/acronym of the SSID words (people abbreviate the network name)."""
    words = [w for w in re.split(r"\s+", t.ssid.strip()) if w]
    alpha = [w for w in words if w[:1].isalpha()]
    outs: list[str] = []
    if alpha:
        f = alpha[0][0]
        outs += [f.upper(), f.lower()]                       # 'A', 'a'
        acr = "".join(w[0] for w in alpha)
        if len(acr) > 1:
            outs += [acr.upper(), acr.lower(), acr.capitalize()]
    return list(dict.fromkeys(outs))


def _ddmmyyyy(year_lo: int = 1950, year_hi: int = 2029):
    """Yield DDMMYYYY date strings, recent years first (so common dates come
    sooner). '20102000' == 20 Oct 2000."""
    for yyyy in range(year_hi, year_lo - 1, -1):
        for mm in range(1, 13):
            for dd in range(1, 32):
                yield f"{dd:02d}{mm:02d}{yyyy}"


def dated_ssid_candidates(t: Target, n: int) -> list[str]:
    """SSID token + full date (DDMMYYYY), a very common home-router pattern.

    Phase A: each SSID *initial/acronym* gets its full date range first, so an
    abbreviated-name + date passphrase (e.g. 'A' + '20102000') appears early.
    Phase B: the SSID *word* tokens get date-major coverage (recent years first),
    so many name+date combos are reached within budget.
    """
    if not t.ssid or n <= 0:
        return []
    lo, hi = WIFI_MIN, WIFI_MAX
    out: list[str] = []
    seen: set[str] = set()

    def add(w: str) -> bool:
        if w and w not in seen and lo <= len(w) <= hi:
            seen.add(w)
            out.append(w)
        return len(out) < n

    words = [w for w in re.split(r"\s+", t.ssid.strip()) if w]
    joined = "".join(words)
    firstalpha = next((w for w in words if w[:1].isalpha()), joined)
    initials = _ssid_initials(t)
    word_tokens = []
    for w in dict.fromkeys([firstalpha, joined]):
        word_tokens += [w, w.lower(), w.upper(), w.capitalize()]
    word_tokens = [w for w in dict.fromkeys(word_tokens) if w and w not in initials]

    # Phase A: initials, token-major (full date range each)
    for tok in initials:
        for d in _ddmmyyyy(1960, 2025):
            if not add(tok + d):
                return out
    # Phase B: word tokens, date-major (recent years first, all tokens per date)
    for yyyy in range(2025, 1959, -1):
        for mm in range(1, 13):
            for dd in range(1, 32):
                d = f"{dd:02d}{mm:02d}{yyyy}"
                for tok in word_tokens:
                    if not add(tok + d):
                        return out
    return out


def ssid_candidates(t: Target, n: int) -> list[str]:
    """SSID-centric WPA candidates: the network name mutated with the common
    tails people actually use (name + digits/years/specials). This is the single
    most productive source when you know the SSID, so it's generated richly."""
    if not t.ssid or n <= 0:
        return []
    lo, hi = WIFI_MIN, WIFI_MAX
    out: list[str] = []
    seen: set[str] = set()

    def add(w: str) -> None:
        if w and w not in seen and lo <= len(w) <= hi:
            seen.add(w)
            out.append(w)

    raw = t.ssid.strip()
    variants: list[str] = []
    for base in {raw, raw.replace(" ", ""), raw.lower(), raw.upper(),
                 raw.capitalize(), raw.replace(" ", "").lower(),
                 raw.replace(" ", "").upper()}:
        if base:
            variants.append(base)
            variants += list(_leet_variants(base, max_variants=3))
    variants = list(dict.fromkeys(variants))  # de-dupe, keep order

    # rich tail set: specials, short digit runs, every plausible year, PINs, and
    # the tester's own numbers.
    tails = ["", "1", "12", "123", "1234", "12345", "123456", "!", "!!", "@",
             "#", "$", "?", "@123", "123!", "1!", "007", "00", "01", "99", "69",
             "88", "786", "111", "222", "321", "0000", "1111", "1234567",
             "12345678", "!@#", "@#$"]
    tails += [str(y) for y in range(1970, 2030)]      # full realistic year span
    tails += [f"{i:03d}" for i in range(0, 1000)]     # 000-999
    tails += t.numbers + t.years
    heads = ["", "!", "@", "#", "wifi", "my"]

    # SSID + tail (and a few head+SSID+tail); interleave so we don't emit one
    # variant's whole block before the next.
    combos = itertools.product(variants, tails)
    for v, tl in combos:
        add(v + tl)
        if len(out) >= n:
            return out
    for h in heads:
        for v in variants:
            for tl in tails:
                add(h + v + tl)
                if len(out) >= n:
                    return out
    return out


# Sentinel shown in the model picker for the always-present built-in model.
BUILTIN_LABEL = "Built-in (WordForge PW-Markov)"


def _is_ollama_choice(model: str | None) -> bool:
    return bool(model) and not model.startswith("Built-in") and not model.startswith("(")


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def generate(t: Target, profile: str, model: str | None,
             use_leet: bool, length: int, progress=None,
             base_words: list[str] | None = None,
             base_name: str = "Built-in common passwords",
             corporate: bool = False) -> list[str]:
    """Build a de-duplicated, profile-filtered wordlist of EXACTLY `length`
    records (or as close as the sources allow).

    Composition (feature: frequency-based adaptive interleaving):
      * TOP BLOCK  — high-signal targeted context: SSID+date (wifi), blended
        tokens, corporate/seasonal defaults, PCFG-structured + Markov-seeded
        completions, keyword mutations (smart leet), keyboard walks.
      * BODY       — the selected base wordlist kept in its native real-world
        FREQUENCY ORDER (e.g. RockYou), woven together with model/PCFG samples
        using a DIMINISHING curve: few synthetic samples near the high-value top
        of the base, progressively more toward the bottom to reach `length`.
    """
    def report(msg):
        if progress:
            progress(msg)

    if base_words is None:
        base_words = baselist.base_words(profile)

    seen: set[str] = set()
    final: list[str] = []

    def take(words) -> bool:  # returns False once we hit `length`
        for w in words:
            if not w or w in seen:
                continue
            seen.add(w)
            final.append(w)
            if len(final) >= length:
                return False
        return True

    # optional 3rd-party LLM first (usually highest quality)
    if _is_ollama_choice(model):
        try:
            report(f"Querying Ollama model '{model}'...")
            take(apply_profile(ollama_candidates(t, model, profile), profile))
        except Exception as e:  # noqa: BLE001
            report(f"Ollama call failed ({e}); using built-in model + rules.")

    base_pool = apply_profile(list(base_words), profile)

    # Size of the high-signal TOP block.
    #  * wifi: generous — the SSID+date material IS the deliverable, so it gets
    #    all the room the base doesn't need.
    #  * email/account: bound to ~10% (feature D), leaving ~90% for the base +
    #    adaptive AI body so the frequency curve has room to work.
    if profile == "wifi":
        top_cap = (length - len(base_pool)) if len(base_pool) <= length \
            else min(length // 3, 120000)
    else:
        top_cap = max(length // 10, 200)
    top_cap = max(0, min(top_cap, length))

    def top_take(words):
        for w in words:
            if len(final) >= top_cap or len(final) >= length:
                return
            if w and w not in seen:
                seen.add(w)
                final.append(w)

    # ---- TOP BLOCK: targeted, high-probability guesses ---------------------
    if profile == "wifi" and t.ssid:
        report(f"Building SSID+date candidates from '{t.ssid}'...")
        top_take(apply_profile(
            dated_ssid_candidates(t, min(top_cap, 200000)), profile))
        report(f"Building candidates from SSID '{t.ssid}'...")
        top_take(apply_profile(ssid_candidates(t, min(top_cap, 60000)), profile))
    report("Blending target tokens...")
    top_take(apply_profile(blend_candidates(t, profile), profile))
    if corporate:
        report("Corporate / seasonal defaults...")
        top_take(apply_profile(
            corporate_seasonal_candidates(t, profile), profile))
    report("Structure-aware (PCFG) candidates...")
    top_take(apply_profile(pcfg_seeded(t, profile, min(top_cap, 8000)), profile))
    top_take(apply_profile(builtin_seeded(t, profile), profile))
    if t.keywords or t.numbers or t.years:
        report("Keyword mutations (smart leet)...")
        top_take(apply_profile(
            rule_candidates(t, profile, use_leet=use_leet, max_out=5000), profile))
    report("Keyboard walks...")
    top_take(apply_profile(keyboard_walk_candidates(t), profile))
    top_take(apply_profile(
        numeric_heavy_candidates(t, profile, min(top_cap, 20000)), profile))

    # ---- AI SAMPLE STREAM: lazy, profile-filtered, deduped by take() -------
    def ai_stream():
        spins = 0
        cap = length * 30 + 5000
        while spins < cap:
            batch = apply_profile(
                pcfg_free(300) + builtin_free(200)
                + numeric_heavy_candidates(t, profile, 500), profile)
            if not batch:
                break
            for w in batch:
                spins += 1
                yield w

    ai = ai_stream()

    # ---- BODY: base in frequency order, adaptive diminishing AI density ----
    report(f"Interleaving base '{base_name}' (adaptive AI density)...")
    B = len(base_pool)
    remaining = length - len(final)
    if remaining > 0 and B == 0:
        for w in ai:
            if not take([w]):
                break
    elif remaining > 0:
        ai_budget = max(0, remaining - B)   # synthetic samples woven through base
        gamma = 2.2                          # >1 => sparse at top, dense at bottom
        injected = 0
        done = False
        for i, bw in enumerate(base_pool):
            target = int(ai_budget * (i / B) ** gamma)
            while injected < target:
                nxt = next(ai, None)
                if nxt is None:
                    break
                if not take([nxt]):
                    done = True
                    break
                injected += 1
            if done or not take([bw]):
                break
        # top up to the exact requested length with the remaining AI stream
        if len(final) < length:
            for w in ai:
                if not take([w]):
                    break

    report(f"Done: {len(final)} records (base '{base_name}' interleaved).")
    return final

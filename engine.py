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

import itertools
import json
import random
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field

import localmodel
import baselist

OLLAMA_URL = "http://localhost:11434"

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
            variants |= _leet_variants(base, max_variants=3)
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


_LLM_SYSTEM = (
    "You assist an AUTHORIZED penetration tester who is auditing a system they "
    "have written permission to test. Given target context, output plausible "
    "PASSWORD CANDIDATES a real user might have chosen, one per line, no "
    "numbering, no commentary, no code fences. Favor realistic human patterns: "
    "names+years, pet+special chars, keyboard walks, leetspeak, local sports "
    "teams, and simple mutations. Output only candidate strings."
)


def ollama_candidates(t: Target, model: str, profile: str, want: int = 300,
                      timeout: int = 120) -> list[str]:
    ctx_lines = []
    if t.keywords:
        ctx_lines.append("Keywords: " + ", ".join(t.keywords))
    if t.years:
        ctx_lines.append("Relevant years/dates: " + ", ".join(t.years))
    if t.numbers:
        ctx_lines.append("Relevant numbers: " + ", ".join(t.numbers))
    if t.notes:
        ctx_lines.append("Notes: " + t.notes)
    constraint = ("These are Wi-Fi WPA2 passphrases (8-63 chars)."
                  if profile == "wifi" else
                  "These are website/account passwords (usually 6-16 chars).")
    prompt = (
        f"{constraint}\nTarget context:\n" + "\n".join(ctx_lines) +
        f"\n\nProduce up to {want} candidate passwords, one per line."
    )
    payload = {
        "model": model,
        "prompt": prompt,
        "system": _LLM_SYSTEM,
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
             base_name: str = "Built-in common passwords") -> list[str]:
    """Build a de-duplicated, profile-filtered wordlist of EXACTLY `length`
    records (or as close as the sources allow), by *appending onto an existing
    base wordlist* which is included in full.

    Order (targeted, high-signal guesses first, then the whole base, then fill):
      1. SSID-centric candidates (wifi)         + personalized model completions
      2. keyword mutations of the target        + numeric-heavy candidates
      3. the ENTIRE selected base wordlist, appended
      4. fill up to `length` with numeric-heavy candidates, then model samples
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

    full = False

    # optional 3rd-party LLM first (usually highest quality)
    if _is_ollama_choice(model):
        try:
            report(f"Querying Ollama model '{model}'...")
            take(apply_profile(ollama_candidates(t, model, profile), profile))
        except Exception as e:  # noqa: BLE001
            report(f"Ollama call failed ({e}); using built-in model + rules.")

    # Reserve room so the ENTIRE base wordlist is always appended. Targeted
    # additions (SSID/date/keyword/numeric) get the rest, capped so a big base
    # still fits and a small base still leaves room for lots of targeted guesses.
    base_pool = apply_profile(list(base_words), profile)
    if len(base_pool) <= length:
        targeted_cap = length - len(base_pool)
    else:
        targeted_cap = min(length // 3, 120000)
    targeted_cap = max(0, min(targeted_cap, length))

    def targeted_take(words):
        for w in words:
            if len(final) >= targeted_cap or len(final) >= length:
                return
            if w and w not in seen:
                seen.add(w)
                final.append(w)

    # 1. SSID-centric: initial/acronym + date first (high-yield router pattern),
    #    then name + common tails.
    if profile == "wifi" and t.ssid:
        report(f"Building SSID+date candidates from '{t.ssid}'...")
        targeted_take(apply_profile(
            dated_ssid_candidates(t, min(targeted_cap, 200000)), profile))
        report(f"Building candidates from SSID '{t.ssid}'...")
        targeted_take(apply_profile(ssid_candidates(t, min(targeted_cap, 60000)), profile))
    targeted_take(apply_profile(builtin_seeded(t, profile), profile))

    # 2. keyword mutations + numeric-heavy (target-specific additions)
    if t.keywords or t.numbers or t.years:
        report("Keyword mutations...")
        targeted_take(apply_profile(
            rule_candidates(t, profile, use_leet=use_leet, max_out=5000), profile))
    report("Numeric-heavy candidates...")
    targeted_take(apply_profile(
        numeric_heavy_candidates(t, profile, min(targeted_cap, 40000)), profile))

    # 3. append the ENTIRE selected base wordlist
    report(f"Appending base wordlist '{base_name}'...")
    full = not take(base_pool)

    # 4. fill up to the requested length (numeric space is effectively unlimited)
    if not full and len(final) < length:
        report(f"Filling to {length} records...")
        need = length - len(final)
        take(apply_profile(numeric_heavy_candidates(t, profile, need + 500), profile))
        if len(final) < length:
            take(apply_profile(builtin_free(length - len(final) + 500), profile))

    report(f"Done: {len(final)} records (appended onto: {base_name}).")
    return final

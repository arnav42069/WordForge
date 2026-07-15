"""
WordForge — built-in local password model (from scratch, no external runtime).

This is a character-level n-gram (Markov) generative model whose ONLY function is
to produce plausible password candidates for AUTHORIZED security testing. It is
trained at import time on an embedded corpus of *generic* weak-password patterns
(dictionary words + common numeric/symbol suffixes and well-known weak passwords
like "qwerty"/"password"). It contains no personal data and never touches the
network — so WordForge always has a working local model even when Ollama is
absent.

How it helps: the model learns the *shape* of real passwords (word-like stem,
then digits, then a symbol) and can (a) emit novel free samples from that learned
distribution and (b) "complete" a context token (e.g. a pet name) with a
realistic learned tail.
"""

from __future__ import annotations

import random
import json
import re

import baselist

ORDER = 3
START = "\x02"
END = "\x03"

# Generic dictionary stems people build passwords from (no personal data).
_WORDS = [
    "love", "dragon", "monkey", "sunshine", "shadow", "master", "ninja",
    "football", "baseball", "princess", "summer", "winter", "spring", "autumn",
    "hunter", "ranger", "jordan", "michael", "jennifer", "superman", "batman",
    "welcome", "computer", "flower", "orange", "purple", "silver", "golden",
    "tiger", "eagle", "falcon", "phoenix", "thunder", "storm", "rocket",
    "guitar", "cookie", "coffee", "chocolate", "diamond", "crystal", "angel",
    "cherry", "pepper", "ginger", "buddy", "charlie", "lucky", "smokey",
    "captain", "warrior", "legend", "matrix", "ocean", "river", "mountain",
    "galaxy", "cosmos", "rebel", "viking", "samurai", "wizard", "knight",
    "liverpool", "chelsea", "arsenal", "cowboys", "lakers", "yankees",
]

# Well-known weak passwords / keyboard walks (public, generic).
_KNOWN = [
    "password", "passw0rd", "p@ssword", "p@ssw0rd", "qwerty", "qwerty123",
    "123456", "1234567", "12345678", "123456789", "letmein", "iloveyou",
    "admin", "administrator", "welcome1", "trustno1", "abc123", "abcd1234",
    "qazwsx", "zaq12wsx", "1q2w3e4r", "1qaz2wsx", "asdfghjkl", "qwertyuiop",
    "iloveyou1", "monkey123", "dragon123", "football1", "sunshine1",
    "changeme", "secret", "login", "starwars", "whatever", "freedom",
]

_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456", "!", "!!", "@", "#", "$",
    "01", "07", "69", "99", "00", "000", "007", "88", "77",
    "2018", "2019", "2020", "2021", "2022", "2023", "2024", "2025",
    "123!", "1!", "!@#", "@123",
]


def _build_corpus() -> list[str]:
    corpus: list[str] = []
    for w in _WORDS:
        forms = {w, w.capitalize(), w.upper()}
        for form in forms:
            for suf in _SUFFIXES:
                corpus.append(form + suf)
    for k in _KNOWN:
        corpus.append(k)
        for suf in ("", "1", "123", "!", "2024", "2025"):
            corpus.append(k + suf)
    # Also learn the *shape* of real public common passwords (rockyou/SecLists
    # style). This teaches the model realistic human patterns without any
    # personal data or breach combolists.
    corpus += baselist.COMMON_PASSWORDS
    corpus += baselist.WIFI_COMMON
    return corpus


class PasswordModel:
    """Char-level Markov model with order back-off (order 3 -> 2 -> 1)."""

    def __init__(self, order: int = ORDER):
        self.order = order
        # maps[k] : context-of-length-k -> {next_char: count}
        self.maps: list[dict[str, dict[str, int]]] = [dict() for _ in range(order + 1)]

    # --- training ---------------------------------------------------------- #
    def train(self, strings: list[str]) -> "PasswordModel":
        for s in strings:
            padded = START * self.order + s + END
            for i in range(self.order, len(padded)):
                nxt = padded[i]
                for k in range(1, self.order + 1):
                    ctx = padded[i - k:i]
                    self.maps[k].setdefault(ctx, {})
                    self.maps[k][ctx][nxt] = self.maps[k][ctx].get(nxt, 0) + 1
        return self

    def _next(self, context: str) -> str | None:
        for k in range(self.order, 0, -1):
            ctx = context[-k:] if len(context) >= k else None
            if ctx is None:
                continue
            dist = self.maps[k].get(ctx)
            if dist:
                chars = list(dist.keys())
                weights = list(dist.values())
                return random.choices(chars, weights=weights, k=1)[0]
        return None

    # --- generation -------------------------------------------------------- #
    def sample(self, min_len: int = 6, max_len: int = 16) -> str:
        out: list[str] = []
        context = START * self.order
        while len(out) < max_len:
            nxt = self._next(context)
            if nxt is None or nxt == END:
                if len(out) >= min_len:
                    break
                # too short; nudge restart from padding
                if nxt == END:
                    context = START * self.order
                    continue
                break
            out.append(nxt)
            context += nxt
        return "".join(out)

    def word_of_length(self, n: int) -> str:
        """Return an ALPHA-only string of exactly ``n`` chars, sampled from the
        learned distribution where possible. Used by the PCFG to fill the alpha
        slots of a chosen structure with realistic, model-generated letters."""
        if n <= 0:
            return ""
        best = ""
        for _ in range(4):
            s = re.sub(r"[^A-Za-z]", "", self.sample())
            if len(s) >= n:
                return s[:n].lower()
            if len(s) > len(best):
                best = s
        # pad with frequency-ish English letters if the sample was too short
        letters = "etaoinshrdlcumwfgypbvkjxqz"
        best = (best + "".join(random.choice(letters) for _ in range(n)))
        return best[:n].lower()

    def complete(self, seed: str, max_len: int = 20) -> str:
        """Append a learned, realistic tail (digits/symbols) to a seed token."""
        out = list(seed)
        context = (START * self.order + seed)
        while len(out) < max_len:
            nxt = self._next(context)
            if nxt is None or nxt == END:
                break
            out.append(nxt)
            context += nxt
        return "".join(out)

    # --- persistence (so the model can ship as a file if desired) ---------- #
    def to_json(self) -> str:
        return json.dumps({"order": self.order, "maps": self.maps})

    @classmethod
    def from_json(cls, text: str) -> "PasswordModel":
        data = json.loads(text)
        m = cls(order=data["order"])
        m.maps = [{k: dict(v) for k, v in mp.items()} for mp in data["maps"]]
        return m


# Trained once at import — this is the shipped local model.
_MODEL: PasswordModel | None = None


def get_model() -> PasswordModel:
    global _MODEL
    if _MODEL is None:
        _MODEL = PasswordModel().train(_build_corpus())
    return _MODEL


def reseed_from_words(words: list[str], keep_builtin: bool = True) -> PasswordModel:
    """Retrain the model, folding in an external public wordlist so free
    samples resemble real-world passwords from that corpus."""
    global _MODEL
    corpus = (_build_corpus() if keep_builtin else []) + list(words)
    _MODEL = PasswordModel().train(corpus)
    return _MODEL


def generate(seed_tokens: list[str] | None = None,
             n_free: int = 250, n_seeded: int = 4) -> list[str]:
    """Return model-generated candidates.

    n_free   : novel passwords sampled from the learned distribution.
    n_seeded : learned-tail completions per seed token.
    """
    model = get_model()
    out: list[str] = []

    for _ in range(n_free):
        s = model.sample()
        if s:
            out.append(s)

    for tok in (seed_tokens or []):
        base = tok.strip()
        if not base:
            continue
        for _ in range(n_seeded):
            c = model.complete(base)
            if c and c != base:
                out.append(c)

    # de-dupe, preserve order
    seen: set[str] = set()
    uniq = []
    for w in out:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    return uniq


if __name__ == "__main__":  # quick self-test / corpus stats
    m = get_model()
    print("corpus size:", len(_build_corpus()))
    print("free samples:", [m.sample() for _ in range(10)])
    print("completions of 'griffin':", [m.complete("griffin") for _ in range(6)])

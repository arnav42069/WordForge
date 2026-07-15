"""
WordForge — Probabilistic Context-Free Grammar (PCFG) password model.

This is the structural counterpart to the character-level Markov model in
``localmodel.py``. Where the Markov chain predicts the next *character*, the
PCFG learns the *shape* of real passwords and then fills that shape in.

Approach (Weir et al. "Password Cracking Using PCFGs", adapted):
  1. At train time, every password is reduced to a STRUCTURE by run-length
     encoding its character classes:
         U = uppercase run, L = lowercase run, D = digit run, S = special run
     e.g.  "Bella1998!"  ->  U1 L4 D4 S1   (written "U1L4D4S1")
  2. Structure frequencies are counted; common structures are sampled in
     proportion to how often they occur in the corpus.
  3. Each structure is then REALIZED (filled):
        * alpha blocks  -> a real learned fragment, a user context token, or a
                           Markov-generated string of the right length,
        * digit runs    -> the tester's years/numbers when the length matches,
                           else a learned/random digit run,
        * special runs  -> a learned/common symbol run.

It holds NO personal data of its own — it is trained on the same public,
PII-stripped password corpora the rest of WordForge uses.
"""

from __future__ import annotations

import random
import re

from collections import Counter, defaultdict

import baselist
import localmodel

# Bounds that keep startup parsing fast and memory small even on a big corpus.
_MAX_TRAIN = 200_000        # passwords scanned to build the grammar
_MAX_PW_LEN = 40            # ignore absurdly long lines
_TOP_TEMPLATES = 600        # keep only the most common structures
_TOP_TERMS = 250            # keep only the most common fragments per bucket

_COMMON_SPECIALS = ["!", "@", "#", "$", "!!", "!@#", "*", "?", ".", "_", "-"]
_COMMON_DIGITS = ["1", "12", "123", "1234", "12345", "123456", "0", "01", "00",
                  "007", "69", "99", "2020", "2021", "2022", "2023", "2024",
                  "2025", "2026"]


def _classify(ch: str) -> str:
    if ch.islower():
        return "L"
    if ch.isupper():
        return "U"
    if ch.isdigit():
        return "D"
    return "S"


def _template(pw: str) -> tuple[tuple[str, int], ...]:
    """Run-length encode a password into (class, length) segments."""
    segs: list[list] = []
    for ch in pw:
        c = _classify(ch)
        if segs and segs[-1][0] == c:
            segs[-1][1] += 1
        else:
            segs.append([c, 1])
    return tuple((c, n) for c, n in segs)


def _to_blocks(tmpl: tuple[tuple[str, int], ...]) -> list[tuple[str, int, str | None]]:
    """Merge adjacent alpha runs into a single 'A' block carrying a case MASK
    (so 'Bella' = U1L4 becomes one block of length 5 with mask 'ULLLL'). Digit
    and special runs pass through as ('D', n, None) / ('S', n, None)."""
    blocks: list[list] = []
    for c, n in tmpl:
        if c in ("U", "L"):
            mask = c * n
            if blocks and blocks[-1][0] == "A":
                blocks[-1][1] += n
                blocks[-1][2] += mask
            else:
                blocks.append(["A", n, mask])
        else:
            blocks.append([c, n, None])
    return [(k, n, m) for k, n, m in blocks]


def _apply_mask(token: str, mask: str) -> str:
    return "".join(ch.upper() if m == "U" else ch.lower()
                   for ch, m in zip(token, mask))


def _pick(bucket, rng: random.Random):
    """bucket == (items, weights); weighted choice or None if empty."""
    if not bucket or not bucket[0]:
        return None
    return rng.choices(bucket[0], weights=bucket[1], k=1)[0]


class PCFGModel:
    def __init__(self):
        self.templates: list[tuple] = []          # ordered by frequency
        self._tmpl_weights: list[int] = []
        self._by_block_len: dict[int, tuple] = {}  # alpha-block-len -> (tmpls, weights)
        self.alpha: dict[int, tuple] = {}          # length -> (fragments, weights)
        self.digit: dict[int, tuple] = {}
        self.special: dict[int, tuple] = {}
        self.trained = False

    # --- training ---------------------------------------------------------- #
    def train(self, passwords) -> "PCFGModel":
        tcount: Counter = Counter()
        alpha: dict[int, Counter] = defaultdict(Counter)
        digit: dict[int, Counter] = defaultdict(Counter)
        special: dict[int, Counter] = defaultdict(Counter)

        for i, pw in enumerate(passwords):
            if i >= _MAX_TRAIN:
                break
            if not pw or len(pw) > _MAX_PW_LEN:
                continue
            tmpl = _template(pw)
            tcount[tmpl] += 1
            idx = 0
            for c, n in tmpl:
                seg = pw[idx:idx + n]
                idx += n
                if c in ("U", "L"):
                    if n <= 20:
                        alpha[n][seg.lower()] += 1
                elif c == "D":
                    if n <= 10:
                        digit[n][seg] += 1
                else:
                    if n <= 6:
                        special[n][seg] += 1

        top = tcount.most_common(_TOP_TEMPLATES)
        self.templates = [t for t, _ in top]
        self._tmpl_weights = [w for _, w in top]

        # index templates by the length of their (first) alpha block, so a user
        # token can be dropped into a structure of the exact right size.
        by_len: dict[int, list[tuple[tuple, int]]] = defaultdict(list)
        for t, w in top:
            for kind, length, _mask in _to_blocks(t):
                if kind == "A":
                    by_len[length].append((t, w))
        self._by_block_len = {
            L: ([t for t, _ in lst], [w for _, w in lst])
            for L, lst in by_len.items()
        }

        def finalize(d: dict[int, Counter]) -> dict[int, tuple]:
            out = {}
            for L, ctr in d.items():
                items = ctr.most_common(_TOP_TERMS)
                out[L] = ([s for s, _ in items], [c for _, c in items])
            return out

        self.alpha = finalize(alpha)
        self.digit = finalize(digit)
        self.special = finalize(special)
        self.trained = bool(self.templates)
        return self

    # --- realization helpers ---------------------------------------------- #
    def _fill_alpha(self, length: int, mask: str, rng: random.Random) -> str:
        frag = _pick(self.alpha.get(length), rng)
        if frag is None or rng.random() < 0.25:
            # ask the Markov chain for a length-exact alpha fill (feature: PCFG
            # structure + Markov terminals working together).
            frag = localmodel.get_model().word_of_length(length)
        frag = (frag or "")[:length].ljust(length, "x")[:length]
        return _apply_mask(frag, mask)

    def _fill_digit(self, length, years, numbers, rng: random.Random) -> str:
        if length == 4 and years and rng.random() < 0.6:
            y = rng.choice(years)
            if len(y) == 4:
                return y
        matches = [x for x in numbers if len(x) == length]
        if matches and rng.random() < 0.6:
            return rng.choice(matches)
        frag = _pick(self.digit.get(length), rng)
        if frag is not None:
            return frag
        return "".join(rng.choice("0123456789") for _ in range(length))

    def _fill_special(self, length, rng: random.Random) -> str:
        frag = _pick(self.special.get(length), rng)
        if frag is not None:
            return frag
        pool = [s for s in _COMMON_SPECIALS if len(s) == length] or ["!"]
        return rng.choice(pool)[:length].ljust(length, "!")[:length]

    def _choose_template(self, token: str | None, rng: random.Random):
        if token and len(token) in self._by_block_len and rng.random() < 0.85:
            b = self._by_block_len[len(token)]
            return rng.choices(b[0], weights=b[1], k=1)[0]
        return rng.choices(self.templates, weights=self._tmpl_weights, k=1)[0]

    def _realize(self, tmpl, token, years, numbers, rng: random.Random) -> str:
        parts: list[str] = []
        placed = False
        for kind, length, mask in _to_blocks(tmpl):
            if kind == "A":
                if token and not placed and len(token) == length:
                    parts.append(_apply_mask(token, mask))
                    placed = True
                else:
                    parts.append(self._fill_alpha(length, mask, rng))
            elif kind == "D":
                parts.append(self._fill_digit(length, years, numbers, rng))
            else:
                parts.append(self._fill_special(length, rng))
        return "".join(parts)

    # --- generation -------------------------------------------------------- #
    def generate(self, n: int, tokens=None, years=None, numbers=None,
                 rng: random.Random | None = None) -> list[str]:
        if not self.trained or n <= 0:
            return []
        rng = rng or random
        toks = [re.sub(r"[^A-Za-z]", "", t) for t in (tokens or [])]
        toks = [t for t in toks if t]
        yrs = [re.sub(r"\D", "", y) for y in (years or [])]
        yrs = [y for y in yrs if y]
        nums = [re.sub(r"\D", "", x) for x in (numbers or [])]
        nums = [x for x in nums if x]

        out: list[str] = []
        seen: set[str] = set()
        tries = 0
        limit = n * 8 + 100
        while len(out) < n and tries < limit:
            tries += 1
            token = (rng.choice(toks) if toks and rng.random() < 0.8 else None)
            tmpl = self._choose_template(token, rng)
            pw = self._realize(tmpl, token, yrs, nums, rng)
            if pw and pw not in seen:
                seen.add(pw)
                out.append(pw)
        return out


# --------------------------------------------------------------------------- #
# Module singleton (mirrors localmodel's lifecycle)
# --------------------------------------------------------------------------- #

_PCFG: PCFGModel | None = None


def _default_corpus() -> list[str]:
    return list(baselist.COMMON_PASSWORDS) + list(baselist.WIFI_COMMON)


def get_pcfg() -> PCFGModel:
    global _PCFG
    if _PCFG is None:
        _PCFG = PCFGModel().train(_default_corpus())
    return _PCFG


def reseed(words: list[str], keep_builtin: bool = True) -> PCFGModel:
    """Rebuild the grammar from a (public, PII-stripped) wordlist so the mined
    structures reflect that corpus' real-world distribution."""
    global _PCFG
    corpus = (_default_corpus() if keep_builtin else []) + list(words)
    _PCFG = PCFGModel().train(corpus)
    return _PCFG


if __name__ == "__main__":  # quick self-test
    m = get_pcfg()
    print("templates:", len(m.templates))
    print("top structures:")
    for t, w in zip(m.templates[:8], m._tmpl_weights[:8]):
        print("  ", "".join(f"{c}{n}" for c, n in t), w)
    print("free:", m.generate(10))
    print("seeded 'Bella'/1998:",
          m.generate(10, tokens=["Bella"], years=["1998"]))

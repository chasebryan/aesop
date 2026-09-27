"""
aesop.core.score — "does this look like English?"

The heart of every automatic classical solver.  A cipher-breaker is only as
good as its fitness function: hill-climbing on a substitution cipher, ranking
Caesar shifts, or scoring a candidate Vigenère key all reduce to *how
English-like is this text?*.

We provide:

* :class:`QuadgramScorer` — log-probability of 4-grams (the gold-standard
  fitness function for monoalphabetic breaking).
* :func:`index_of_coincidence` — Friedman's IC, for cipher classification and
  Vigenère key-length detection.
* :func:`chi_squared` — goodness-of-fit against English letter frequencies,
  used to lock each Caesar shift of a Vigenère column.
* :func:`shannon_entropy` — bits/byte, for spotting compression/encryption.

The quadgram model lives in ``aesop/data/english_quadgrams.txt.gz`` and is
loaded lazily.  If it is missing, the scorer transparently falls back to a
bigram/letter-frequency model so the tool still works out of the box.
"""
from __future__ import annotations

import gzip
import math
import os
import re
from collections import Counter
from functools import lru_cache
from typing import Dict, Iterable, Optional

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
_QUADGRAM_FILE = os.path.join(_DATA_DIR, "english_quadgrams.txt.gz")

# Standard English monogram frequencies (%) — Cornell / concise-oxford blend.
ENGLISH_FREQ: Dict[str, float] = {
    "A": 8.167, "B": 1.492, "C": 2.782, "D": 4.253, "E": 12.702, "F": 2.228,
    "G": 2.015, "H": 6.094, "I": 6.966, "J": 0.153, "K": 0.772, "L": 4.025,
    "M": 2.406, "N": 6.749, "O": 7.507, "P": 1.929, "Q": 0.095, "R": 5.987,
    "S": 6.327, "T": 9.056, "U": 2.758, "V": 0.978, "W": 2.360, "X": 0.150,
    "Y": 1.974, "Z": 0.074,
}

# Common English bigrams (log-ish weights) for the fallback scorer.
_COMMON_BIGRAMS = {
    "TH": 2.71, "HE": 2.33, "IN": 2.03, "ER": 1.78, "AN": 1.61, "RE": 1.41,
    "ND": 1.35, "ON": 1.32, "EN": 1.30, "AT": 1.24, "OU": 1.21, "ED": 1.20,
    "HA": 1.19, "TO": 1.17, "OR": 1.15, "IT": 1.13, "IS": 1.13, "HI": 1.12,
    "ES": 1.11, "NG": 1.05, "ST": 1.05, "AR": 1.04, "TE": 0.99, "NT": 0.97,
    "OF": 0.96, "SE": 0.93, "LE": 0.87, "SA": 0.76, "SI": 0.76, "AL": 0.75,
}

_NONALPHA = re.compile(r"[^A-Z]")


def clean_text(text: str) -> str:
    """Upper-case and strip everything that is not an ASCII letter."""
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("latin-1")
    return _NONALPHA.sub("", text.upper())


class QuadgramScorer:
    """Log10-probability scorer over English quadgrams.

    Higher (closer to 0, less negative) is more English-like.  The score is the
    sum of log-probabilities of each overlapping 4-gram; unseen quadgrams get a
    small floor probability so the score stays finite.
    """

    def __init__(self, path: str = _QUADGRAM_FILE):
        self.counts: Dict[str, int] = {}
        self.total: int = 0
        self.log: Dict[str, float] = {}
        self.floor: float = -8.0
        self.loaded = False
        self._load(path)

    def _load(self, path: str) -> None:
        if not os.path.exists(path):
            return
        try:
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    key, _, cnt = line.partition(" ")
                    if len(key) == 4 and cnt:
                        c = int(cnt)
                        self.counts[key] = c
                        self.total += c
            if self.total:
                self.floor = math.log10(0.01 / self.total)
                for k, c in self.counts.items():
                    self.log[k] = math.log10(c / self.total)
                self.loaded = True
        except Exception:
            self.loaded = False

    def score(self, text: str) -> float:
        """Fitness of ``text`` (higher is better)."""
        t = clean_text(text)
        if len(t) < 4:
            return -999.0 * (4 - len(t))
        if self.loaded:
            log = self.log
            floor = self.floor
            return sum(log.get(t[i : i + 4], floor) for i in range(len(t) - 3))
        return _fallback_score(t)

    def score_normalized(self, text: str) -> float:
        """Per-quadgram average score — comparable across text lengths."""
        t = clean_text(text)
        n = max(1, len(t) - 3)
        return self.score(text) / n


def _fallback_score(t: str) -> float:
    """Bigram + monogram fallback when the quadgram model is unavailable."""
    if not t:
        return -9999.0
    score = 0.0
    for i in range(len(t) - 1):
        score += _COMMON_BIGRAMS.get(t[i : i + 2], -0.2)
    # Reward realistic letter distribution too.
    freq = Counter(t)
    n = len(t)
    for ch, expected in ENGLISH_FREQ.items():
        observed = 100.0 * freq.get(ch, 0) / n
        score -= abs(observed - expected) * 0.05
    return score


@lru_cache(maxsize=1)
def default_scorer() -> QuadgramScorer:
    """Process-wide singleton scorer (model loaded once)."""
    return QuadgramScorer()


def score_text(text: str) -> float:
    """Convenience: fitness of ``text`` using the default scorer."""
    return default_scorer().score(text)


# --------------------------------------------------------------------------- #
# Classic statistics
# --------------------------------------------------------------------------- #
def index_of_coincidence(text: str) -> float:
    """Friedman's Index of Coincidence.

    ~0.0667 for English monoalphabetic text, ~0.0385 for uniform random / a
    polyalphabetic cipher with a long key.  The single most useful number for
    telling substitution from Vigenère.
    """
    t = clean_text(text)
    n = len(t)
    if n < 2:
        return 0.0
    freq = Counter(t)
    return sum(c * (c - 1) for c in freq.values()) / (n * (n - 1))


def chi_squared(text: str, expected: Optional[Dict[str, float]] = None) -> float:
    """Chi-squared distance of ``text`` letter frequencies from English.

    Lower is more English-like.  This is the workhorse for locking a Caesar
    shift (try all 26, keep the smallest chi-squared).
    """
    expected = expected or ENGLISH_FREQ
    t = clean_text(text)
    n = len(t)
    if n == 0:
        return float("inf")
    freq = Counter(t)
    total = 0.0
    for ch, pct in expected.items():
        exp = pct / 100.0 * n
        obs = freq.get(ch, 0)
        if exp > 0:
            total += (obs - exp) ** 2 / exp
    return total


def shannon_entropy(data: bytes | str) -> float:
    """Shannon entropy in bits per symbol (byte for bytes, char for str).

    ~8.0 for encrypted/compressed bytes, ~4.0-4.5 for English text bytes,
    low for structured data.  A fast triage for "is this ciphertext random?".
    """
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def letter_frequencies(text: str) -> Dict[str, float]:
    """Return observed letter frequencies as percentages."""
    t = clean_text(text)
    n = len(t) or 1
    freq = Counter(t)
    return {ch: 100.0 * freq.get(ch, 0) / n for ch in ENGLISH_FREQ}


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (incl. whitespace)."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)

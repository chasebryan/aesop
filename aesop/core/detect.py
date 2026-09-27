"""
aesop.core.detect — "what am I even looking at?"

Triage for an unknown blob.  Before you can break a cipher you have to guess
*which* cipher.  This module scores a piece of data against a battery of
signatures — entropy, index of coincidence, character set, structure — and
returns ranked hypotheses with human-readable reasons.  It powers both the
``aesop identify`` command and the ``aesop auto`` solver.
"""
from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field
from typing import List

from .score import (
    index_of_coincidence,
    shannon_entropy,
    printable_ratio,
    clean_text,
    chi_squared,
)


@dataclass
class Guess:
    """One hypothesis about what a blob is."""

    label: str          # e.g. "base64", "vigenere", "single-byte-xor"
    kind: str           # "encoding" | "classical" | "modern" | "hash" | "plaintext"
    confidence: float   # 0..1
    reason: str         # why we think so
    suggest: str = ""   # the AESOP command to try next

    def __iter__(self):  # allows tuple unpacking in tables
        return iter((self.label, self.kind, f"{self.confidence:.0%}", self.reason, self.suggest))


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #
_HASH_LENGTHS = {32: "md5 / ntlm / md4", 40: "sha1", 56: "sha224",
                 64: "sha256", 96: "sha384", 128: "sha512"}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_\-]+={0,2}$")
_B32_RE = re.compile(r"^[A-Z2-7]+={0,6}$")
_MORSE_RE = re.compile(r"^[.\-/ \t\n]+$")


def _strip_ws(s: str) -> str:
    return re.sub(r"\s", "", s)


def identify(data: bytes) -> List[Guess]:
    """Return ranked hypotheses (highest confidence first) for ``data``."""
    guesses: List[Guess] = []
    text = data.decode("latin-1")
    stripped = _strip_ws(text)
    n = len(stripped)
    pr = printable_ratio(data)
    ent = shannon_entropy(data)

    # ---- Not text at all: high-entropy binary ----------------------------- #
    if pr < 0.75:
        if ent > 7.5:
            guesses.append(Guess(
                "encrypted / compressed", "modern", 0.7,
                f"binary, entropy {ent:.2f} bits/byte (near-random)",
                "aesop entropy   # then try xor / block-cipher analysis"))
        else:
            guesses.append(Guess(
                "binary data", "modern", 0.5,
                f"non-printable ({pr:.0%} printable), entropy {ent:.2f}",
                "aesop entropy"))

    # ---- Morse ------------------------------------------------------------ #
    if n and _MORSE_RE.match(text) and ("." in text or "-" in text):
        guesses.append(Guess("morse code", "encoding", 0.9,
                             "only dots, dashes and separators", "aesop morse"))

    # ---- Hash by shape ---------------------------------------------------- #
    if n in _HASH_LENGTHS and _HEX_RE.match(stripped):
        guesses.append(Guess(
            f"hash ({_HASH_LENGTHS[n]})", "hash", 0.8,
            f"{n} hex chars — classic digest length",
            "aesop hash-id   # then aesop crack"))

    # ---- Encodings -------------------------------------------------------- #
    if n >= 4 and _HEX_RE.match(stripped) and n % 2 == 0:
        conf = 0.6 + 0.2 * (any(c.isdigit() for c in stripped))
        guesses.append(Guess("hex", "encoding", min(conf, 0.9),
                             "even length, all hex digits", "aesop from-hex"))
    if n >= 8 and n % 4 == 0 and _B64_RE.match(stripped) and any(c.isdigit() or c in "+/=" for c in stripped):
        guesses.append(Guess("base64", "encoding", 0.75,
                             "length %4==0, base64 alphabet", "aesop b64 -d"))
    if n >= 8 and _B64URL_RE.match(stripped) and ("-" in stripped or "_" in stripped):
        guesses.append(Guess("base64url", "encoding", 0.7,
                             "URL-safe base64 alphabet ('-'/'_')", "aesop b64 -d --url"))
    if n >= 8 and n % 8 == 0 and _B32_RE.match(stripped):
        guesses.append(Guess("base32", "encoding", 0.65,
                             "A-Z2-7 alphabet, length %8==0", "aesop from-base32"))

    # ---- Alphabetic classical ciphers ------------------------------------ #
    alpha = clean_text(text)
    if len(alpha) >= 20 and len(alpha) / max(1, len(text)) > 0.5:
        ic = index_of_coincidence(text)
        chi = chi_squared(text)
        if ic > 0.06:
            # Monoalphabetic: could be plaintext, Caesar, or substitution.
            if chi < 60:
                guesses.append(Guess("plaintext (or Caesar)", "plaintext", 0.7,
                                     f"IC {ic:.3f} (English-like), low chi² {chi:.0f}",
                                     "aesop caesar   # if not already readable"))
            else:
                guesses.append(Guess("monoalphabetic substitution", "classical", 0.72,
                                     f"IC {ic:.3f} (English-like) but chi² {chi:.0f} (letters remapped)",
                                     "aesop substitution"))
                guesses.append(Guess("caesar / rot-n", "classical", 0.5,
                                     f"IC {ic:.3f} — try the cheap shift solve first",
                                     "aesop caesar"))
        elif 0.038 <= ic <= 0.06:
            guesses.append(Guess("vigenère / polyalphabetic", "classical", 0.72,
                                 f"IC {ic:.3f} (below English 0.066 — repeating key)",
                                 "aesop vigenere"))
        else:
            guesses.append(Guess("polyalphabetic (long key) or transposed", "classical", 0.45,
                                 f"IC {ic:.3f} (near-random for letters)",
                                 "aesop vigenere / aesop transposition"))

        # Transposition leaves the letter distribution intact.
        if chi < 60 and ic > 0.06:
            guesses.append(Guess("transposition (anagram)", "classical", 0.4,
                                 f"English letter frequencies (chi² {chi:.0f}) but may be scrambled",
                                 "aesop transposition"))

    # ---- Readable already? ------------------------------------------------ #
    if pr > 0.95 and _looks_english(text):
        guesses.append(Guess("readable text", "plaintext", 0.85,
                             "already printable and English-like", "(nothing to do)"))

    if not guesses:
        guesses.append(Guess("unknown", "modern", 0.2,
                             f"no strong signature (printable {pr:.0%}, entropy {ent:.2f})",
                             "aesop entropy / aesop magic"))

    guesses.sort(key=lambda g: g.confidence, reverse=True)
    return guesses


def _looks_english(text: str) -> bool:
    words = re.findall(r"[A-Za-z]{2,}", text)
    if len(words) < 3:
        return False
    common = {"the", "and", "of", "to", "a", "in", "is", "it", "you", "that",
              "he", "was", "for", "on", "are", "with", "as", "his", "they"}
    lower = [w.lower() for w in words]
    hits = sum(1 for w in lower if w in common)
    return hits >= max(1, len(words) // 20)

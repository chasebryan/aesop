"""
aesop.analysis.freq_cmd — the ``freq`` frequency-analysis command.

Frequency analysis is the ninth-century idea (al-Kindi) that broke the
monoalphabetic cipher and never stopped being useful: **letters betray
themselves by how often they turn up.**  In the fable, the tortoise wins not by
speed but by steady counting — and so does the cryptanalyst.

This command gathers, in one screen, the four things you look at first on any
alphabetic ciphertext:

* the **letter-frequency profile** against English (is ``E`` still on top?);
* the **index of coincidence** and **chi-squared** distance (mono- vs
  poly-alphabetic; how far from plain English);
* the most common **bigrams and trigrams** (``TH``/``THE`` leak through weak
  ciphers); and
* **Kasiski repeated-substring spacings**, whose common factors betray a
  Vigenère key length.

The heavy statistics live in :mod:`aesop.core.score`; the n-gram and Kasiski
helpers here are small and pure so they can be imported and unit-tested.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, List, Tuple

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import (
    clean_text,
    letter_frequencies,
    index_of_coincidence,
    chi_squared,
    ENGLISH_FREQ,
)


# --------------------------------------------------------------------------- #
# Programmatic API
# --------------------------------------------------------------------------- #
def ngram_counts(text: str, n: int) -> Counter:
    """Count overlapping ``n``-grams of the letters-only form of ``text``."""
    t = clean_text(text)
    if len(t) < n:
        return Counter()
    return Counter(t[i : i + n] for i in range(len(t) - n + 1))


def repeated_substrings(text: str, length: int = 3) -> Dict[str, List[int]]:
    """Positions of every length-``length`` substring that occurs more than once."""
    t = clean_text(text)
    pos: Dict[str, List[int]] = {}
    for i in range(len(t) - length + 1):
        pos.setdefault(t[i : i + length], []).append(i)
    return {g: p for g, p in pos.items() if len(p) > 1}


def kasiski_factors(text: str, length: int = 3, max_len: int = 20) -> Tuple[Counter, List[int]]:
    """Kasiski examination.

    Find repeated substrings, measure the gaps between consecutive occurrences,
    and tally which candidate key lengths (2..``max_len``) divide those gaps.
    Returns ``(factor_counts, spacings)`` where ``factor_counts[k]`` is how often
    ``k`` divides an observed spacing — the peak is the likely Vigenère period.
    """
    factor_counts: Counter = Counter()
    spacings: List[int] = []
    for positions in repeated_substrings(text, length).values():
        for a, b in zip(positions, positions[1:]):
            d = b - a
            if d <= 0:
                continue
            spacings.append(d)
            for k in range(2, max_len + 1):
                if d % k == 0:
                    factor_counts[k] += 1
    return factor_counts, spacings


def likely_key_lengths(text: str, top: int = 5, length: int = 3, max_len: int = 20) -> List[Tuple[int, int]]:
    """Return the ``top`` most-supported Vigenère key lengths as ``(k, votes)``."""
    factor_counts, _ = kasiski_factors(text, length=length, max_len=max_len)
    return factor_counts.most_common(top)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "freq",
    group="analysis",
    summary="Frequency analysis: letter profile, IC, chi², n-grams, Kasiski",
    manual="frequency",
    aliases=["frequency"],
    args=io_args(
        positional="text",
        positional_help="the ciphertext to profile (or pipe via stdin / use --file)",
    )
    + [
        arg("--ngrams", "also list the top n-grams of this length (e.g. 4)", type=int),
    ],
    examples=[
        "aesop freq 'Lxfopvefrnhr ...'",
        "echo 'Wkh txlfn eurzq ira' | aesop freq",
        "aesop freq -f ciphertext.txt",
        "aesop freq --ngrams 8 'Lxfopvefrnhr'",
    ],
    description="""
        The cryptanalyst's dashboard for any alphabetic ciphertext.  ``freq``
        counts letters and compares them to English, reports the index of
        coincidence and chi-squared distance, surfaces the top bigrams and
        trigrams, and runs a Kasiski examination whose repeated-gap factors hint
        at a Vigenère key length.  Use it to decide *which* solver to run:
        IC near 0.066 ⇒ Caesar/substitution; IC near 0.04 ⇒ Vigenère, and the
        key-length table tells you the period.
    """,
)
def cmd_freq(args, out) -> int:
    inp = _load_literal(args)
    text = inp.text
    letters = clean_text(text)
    if not letters:
        out.error("no letters to analyse (frequency analysis needs alphabetic text)")
        return 2

    freqs = letter_frequencies(text)  # {'A': pct, ...}
    ic = index_of_coincidence(text)
    chi = chi_squared(text)

    # PRIMARY, pipe-friendly result: the observed letter profile on one line.
    out.raw(" ".join(f"{ch}:{freqs[ch]:.2f}" for ch in sorted(ENGLISH_FREQ)))

    # --- letter frequency vs English, with a little bar ------------------- #
    out.print()
    rows = []
    for ch in sorted(ENGLISH_FREQ, key=lambda c: freqs[c], reverse=True):
        obs = freqs[ch]
        exp = ENGLISH_FREQ[ch]
        bar = "█" * int(round(obs / 2.0))
        rows.append((ch, f"{obs:5.2f}%", f"{exp:5.2f}%", f"{obs - exp:+5.2f}", bar))
    out.table(
        ["letter", "observed", "english", "delta", ""],
        rows,
        title=f"letter frequencies ({len(letters)} letters)",
    )

    # --- IC & chi-squared, with a verdict --------------------------------- #
    verdict = _classify(ic)
    out.print()
    out.keyval(
        [
            ("index of coincidence", f"{ic:.4f}   (English ≈ 0.0667, random ≈ 0.0385)"),
            ("chi² vs English", f"{chi:.1f}   (lower = closer to plain English)"),
            ("likely family", verdict),
        ],
        title="statistics",
    )

    # --- top bigrams / trigrams ------------------------------------------- #
    bi = ngram_counts(text, 2).most_common(10)
    tri = ngram_counts(text, 3).most_common(10)
    if bi:
        out.print()
        out.table(
            ["bigram", "count", "trigram", "count"],
            [
                (
                    bi[i][0] if i < len(bi) else "",
                    bi[i][1] if i < len(bi) else "",
                    tri[i][0] if i < len(tri) else "",
                    tri[i][1] if i < len(tri) else "",
                )
                for i in range(max(len(bi), len(tri)))
            ],
            title="most common n-grams (English: TH/HE/IN, THE/AND/ING)",
        )

    # --- optional larger repeated n-gram inspection ----------------------- #
    span = getattr(args, "ngrams", None)
    if span:
        big = ngram_counts(text, span).most_common(10)
        if big:
            out.print()
            out.table(
                [f"{span}-gram", "count"],
                [(g, c) for g, c in big if c > 1] or [(g, c) for g, c in big],
                title=f"top {span}-grams",
            )

    # --- Kasiski key-length hints ----------------------------------------- #
    hints = likely_key_lengths(text, top=6)
    if hints:
        out.print()
        out.table(
            ["key length", "supporting spacings"],
            [(k, "▇" * min(v, 40) + f" {v}") for k, v in hints],
            title="Kasiski key-length hints (Vigenère period)",
        )
        best_k = hints[0][0]
        if 0.038 <= ic <= 0.062:
            out.hint(f"next: aesop vigenere --key-length {best_k}   # or let it auto-solve")
    elif 0.038 <= ic <= 0.062:
        out.hint("IC suggests Vigenère but no repeats found — try `aesop vigenere` (auto key length)")
    elif ic > 0.062:
        out.hint("IC is English-like — try `aesop caesar` or `aesop substitution`")

    return 0


def _classify(ic: float) -> str:
    if ic > 0.062:
        return "monoalphabetic (Caesar / substitution / plaintext)"
    if 0.038 <= ic <= 0.062:
        return "polyalphabetic (Vigenère / repeating key)"
    return "long-key polyalphabetic or non-letter data"


# --------------------------------------------------------------------------- #
# Shared input handling (mirrors detect_cmd / entropy_cmd)
# --------------------------------------------------------------------------- #
def _load_literal(args):
    """Load the literal input, never auto-decoding (see detect_cmd for why)."""
    ue = getattr(args, "in_encoding", "auto") or "auto"
    if ue != "auto":
        return io.load(args, encoding=ue)
    return io.load(args, binary=True, encoding="raw")

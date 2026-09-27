"""
aesop.gui.insight — at-a-glance statistics for whatever is in the input box.

The workbench's inspector shows these live while you type or load a file: how
AESOP will decode the input, the numbers a cryptanalyst checks first (entropy,
Index of Coincidence), what the data probably is, and the series behind the
charts.  Everything is computed with the same functions the ``identify``,
``freq`` and ``entropy`` commands use.

Toolkit-free.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..analysis.entropy_cmd import sliding_entropy
from ..core import io
from ..core.detect import Guess, identify
from ..core.score import (ENGLISH_FREQ, clean_text, index_of_coincidence,
                          letter_frequencies, printable_ratio, shannon_entropy)

# Statistics are computed over at most this much data so typing stays smooth.
SAMPLE_LIMIT = 256 * 1024

IC_ENGLISH = 0.0667
IC_RANDOM = 0.0385


@dataclass
class Insight:
    size: int = 0                     # decoded length in bytes
    sampled: int = 0                  # how many of those the numbers cover
    encoding: str = "raw"             # how the input was read for analysis
    sniffed: str = ""                 # what a solver's autodetect would decode it as
    source: str = "literal"
    entropy: float = 0.0              # bits per byte
    printable: float = 0.0            # 0..1
    letters: int = 0
    ic: Optional[float] = None        # None when there are too few letters
    guesses: List[Guess] = field(default_factory=list)
    letter_freq: Dict[str, float] = field(default_factory=dict)   # percent
    byte_counts: List[int] = field(default_factory=list)          # 256 bins
    entropy_series: List[Tuple[int, float]] = field(default_factory=list)
    error: str = ""

    @property
    def empty(self) -> bool:
        return self.size == 0

    @property
    def texty(self) -> bool:
        """Mostly letters and printable — letter statistics are meaningful."""
        return self.printable >= 0.9 and self.letters >= 0.5 * max(1, self.sampled)

    @property
    def ic_reading(self) -> str:
        if self.ic is None:
            return "too few letters"
        if self.ic >= 0.060:
            return "English-like: plaintext or monoalphabetic"
        if self.ic >= 0.045:
            return "in between: short-key polyalphabetic"
        return "flat: long key or random"

    @property
    def entropy_reading(self) -> str:
        if self.entropy >= 7.5:
            return "near-random: encrypted or compressed"
        if self.entropy >= 6.0:
            return "dense: encoded or mixed binary"
        if self.entropy >= 3.5:
            return "text-like"
        return "low: repetitive or tiny alphabet"


def analyse(text: Optional[str], *, encoding: str = "auto",
            file: Optional[str] = None) -> Insight:
    """Inspect a literal ``text`` or, when given, the contents of ``file``.

    Like the ``identify``/``freq``/``entropy`` commands, this looks at the
    input *as given* unless an explicit ``encoding`` asks for it to be decoded
    first — otherwise a base64 string would be decoded and no longer look like
    base64.  ``sniffed`` reports what the solvers' autodetect would make of it.
    """
    if not file and not (text or "").strip():
        return Insight()
    explicit = (encoding or "auto") != "auto"
    try:
        if explicit:
            loaded = io.read_input(text, encoding=encoding, from_file=file or None)
        else:
            loaded = io.read_input(text, encoding="raw", from_file=file or None,
                                   binary=True)
    except Exception as exc:          # unreadable file, invalid hex, …
        return Insight(error=f"{type(exc).__name__}: {exc}")
    sniffed = "" if (file or explicit) else io.sniff_encoding((text or "").strip())

    data = loaded.data
    sample = data[:SAMPLE_LIMIT]
    as_text = sample.decode("latin-1")
    letters = len(clean_text(as_text))
    counts = Counter(sample)
    return Insight(
        size=len(data),
        sampled=len(sample),
        encoding=loaded.encoding,
        sniffed="" if sniffed == "raw" else sniffed,
        source=loaded.source,
        entropy=shannon_entropy(sample),
        printable=printable_ratio(sample),
        letters=letters,
        ic=index_of_coincidence(as_text) if letters >= 2 else None,
        guesses=identify(sample)[:4],
        letter_freq=letter_frequencies(as_text) if letters else {},
        byte_counts=[counts.get(b, 0) for b in range(256)],
        entropy_series=sliding_entropy(sample),
    )


def english_frequencies() -> Dict[str, float]:
    """The reference letter profile (percent), for charting against."""
    return dict(ENGLISH_FREQ)

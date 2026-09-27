"""
aesop.analysis.entropy_cmd — the ``entropy`` command.

Entropy is the tell-tale heart of hidden data.  *"The wolf in sheep's clothing"*
still moves like a wolf: encryption and compression flatten a byte distribution
until it looks like pure noise (≈8.0 bits/byte), while structured data —
English text, protocol headers, base64 — carries far less.  Measuring entropy is
the fastest way to answer *"is this random-looking ciphertext, or is there
structure I can attack?"*.

The single-number measure comes straight from
:func:`aesop.core.score.shannon_entropy`.  What this command adds — and keeps as
small, pure, importable helpers — is:

* :func:`sliding_entropy` — entropy across a moving window, so a low-entropy
  header stapled to a high-entropy payload stands out;
* :func:`byte_histogram` — a coarse summary of the byte distribution; and
* :func:`sparkline` — a one-line ASCII picture of how entropy moves through the
  data.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional, Tuple

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import shannon_entropy, printable_ratio


_SPARK = "▁▂▃▄▅▆▇█"


# --------------------------------------------------------------------------- #
# Programmatic API
# --------------------------------------------------------------------------- #
def sliding_entropy(
    data: bytes, window: Optional[int] = None, step: Optional[int] = None
) -> List[Tuple[int, float]]:
    """Shannon entropy over a sliding window.

    Returns ``[(offset, entropy), ...]``.  ``window`` and ``step`` default to
    sensible sizes derived from the input length (so the picture has ~16-64
    samples).  For data shorter than one window a single whole-blob sample is
    returned.  Pure and importable.
    """
    n = len(data)
    if n == 0:
        return []
    if window is None:
        window = max(16, min(256, n // 16 or n))
    if window > n:
        return [(0, shannon_entropy(data))]
    if step is None:
        step = max(1, window // 2)
    out: List[Tuple[int, float]] = []
    for i in range(0, n - window + 1, step):
        out.append((i, shannon_entropy(data[i : i + window])))
    # Always include the tail window so the end of the data is represented.
    if out and out[-1][0] != n - window:
        out.append((n - window, shannon_entropy(data[n - window :])))
    return out


def byte_histogram(data: bytes) -> Dict[str, int]:
    """Coarse byte-distribution summary.

    Returns counts bucketed into the categories that matter for triage:
    ``null`` (0x00), ``control`` (other <0x20 and 0x7f), ``printable``
    (0x20-0x7e), and ``high`` (>=0x80), plus ``distinct`` (number of distinct
    byte values, out of 256).
    """
    freq = Counter(data)
    buckets = {"null": 0, "control": 0, "printable": 0, "high": 0}
    for b, c in freq.items():
        if b == 0:
            buckets["null"] += c
        elif b < 0x20 or b == 0x7F:
            buckets["control"] += c
        elif b < 0x80:
            buckets["printable"] += c
        else:
            buckets["high"] += c
    buckets["distinct"] = len(freq)
    return buckets


def sparkline(values: List[float], vmin: float = 0.0, vmax: float = 8.0) -> str:
    """Render ``values`` as a one-line ASCII sparkline over the range ``[vmin, vmax]``."""
    if not values:
        return ""
    span = (vmax - vmin) or 1.0
    out = []
    for v in values:
        frac = (v - vmin) / span
        idx = int(round(frac * (len(_SPARK) - 1)))
        idx = max(0, min(len(_SPARK) - 1, idx))
        out.append(_SPARK[idx])
    return "".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "entropy",
    group="analysis",
    summary="Measure Shannon entropy (overall + sliding window) to spot random/encrypted data",
    manual="entropy",
    aliases=[],
    args=io_args(
        positional="data",
        positional_help="the data to measure (or pipe via stdin / use --file)",
    )
    + [
        arg("-w --window", "sliding-window size in bytes (default: auto)", type=int),
        arg("-s --step", "sliding-window step in bytes (default: window/2)", type=int),
    ],
    examples=[
        "head -c 4096 /dev/urandom | aesop entropy   # ≈ 8.0",
        "aesop entropy -f suspND.bin",
        "echo 'the quick brown fox' | aesop entropy   # low, English-like",
        "aesop entropy -w 32 -f firmware.bin",
    ],
    description="""
        Entropy triage.  Reports overall Shannon entropy in bits/byte (≈8.0 for
        encrypted or compressed data, ≈4.0-4.5 for English text, low for
        structured formats), then walks a sliding window across the data so a
        low-entropy header or padding region stapled to a high-entropy payload
        jumps out.  A one-line ASCII sparkline shows the shape at a glance, and a
        byte-distribution summary tells you whether the bytes are printable,
        control, or high-bit.  Input is read as raw bytes by default; pass
        ``-e hex``/``base64`` to measure a *decoded* payload instead.
    """,
)
def cmd_entropy(args, out) -> int:
    inp = _load_literal(args)
    data = inp.data
    if not data:
        out.error("no input to measure")
        return 2

    overall = shannon_entropy(data)

    # PRIMARY, pipe-friendly result: the overall entropy on its own line.
    out.raw(f"{overall:.4f}")

    # Sliding window analysis.
    window = getattr(args, "window", None)
    step = getattr(args, "step", None)
    samples = sliding_entropy(data, window=window, step=step)
    values = [e for _, e in samples]

    if len(samples) > 1:
        wsize = min(window or max(16, min(256, len(data) // 16 or len(data))), len(data))
        lo_off, lo_val = min(samples, key=lambda t: t[1])
        hi_off, hi_val = max(samples, key=lambda t: t[1])
        out.print()
        out.raw(sparkline(values))
        out.keyval(
            [
                ("overall entropy", f"{overall:.4f} bits/byte  ({_verdict(overall)})"),
                ("window size", f"{wsize} bytes, {len(samples)} windows"),
                ("minimum", f"{lo_val:.4f} at offset {lo_off}"),
                ("maximum", f"{hi_val:.4f} at offset {hi_off}"),
                ("spread", f"{hi_val - lo_val:.4f}"),
            ],
            title="sliding-window entropy",
        )
    else:
        out.print()
        out.keyval(
            [("overall entropy", f"{overall:.4f} bits/byte  ({_verdict(overall)})")],
            title="entropy",
        )

    # Byte-distribution summary.
    hist = byte_histogram(data)
    n = len(data)
    out.print()
    out.table(
        ["category", "bytes", "share"],
        [
            ("printable (0x20-0x7e)", hist["printable"], f"{hist['printable'] / n:.0%}"),
            ("high (>=0x80)", hist["high"], f"{hist['high'] / n:.0%}"),
            ("control (<0x20, 0x7f)", hist["control"], f"{hist['control'] / n:.0%}"),
            ("null (0x00)", hist["null"], f"{hist['null'] / n:.0%}"),
        ],
        title=f"byte distribution ({hist['distinct']}/256 distinct values)",
    )
    out.keyval(
        [
            ("length", f"{n} bytes"),
            ("printable ratio", f"{printable_ratio(data):.0%}"),
        ]
    )

    if overall > 7.5:
        out.hint("near-random: likely encrypted/compressed — try `aesop identify`, XOR or block-cipher analysis")
    elif overall < 1.5:
        out.hint("very low entropy: highly structured/repetitive data")
    return 0


def _verdict(e: float) -> str:
    if e > 7.5:
        return "random / encrypted / compressed"
    if e > 6.0:
        return "high — encoded or packed"
    if e > 3.5:
        return "text-like"
    return "low — structured / repetitive"


# --------------------------------------------------------------------------- #
# Shared input handling (mirrors detect_cmd / freq_cmd)
# --------------------------------------------------------------------------- #
def _load_literal(args):
    """Load the literal bytes, never auto-decoding.

    Entropy must be measured on the *real* bytes, so ``binary=True`` keeps high
    bytes intact over stdin/files (avoiding a latin-1→utf-8 round-trip that would
    inflate the count) and ``encoding='raw'`` stops a literal argument being
    sniffed as base64/hex.  An explicit ``-e`` decodes first, to measure the
    entropy of the decoded payload.
    """
    ue = getattr(args, "in_encoding", "auto") or "auto"
    if ue != "auto":
        return io.load(args, encoding=ue)
    return io.load(args, binary=True, encoding="raw")

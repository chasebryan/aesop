"""
aesop.analysis.detect_cmd — the ``identify`` triage command.

*"Know thine enemy."*  Before the fox can outwit the crow, it must first know a
crow when it sees one.  Before you can break a cipher, you have to guess *which*
cipher — and that is exactly what this command does.

``identify`` is a thin, pipe-friendly wrapper over :func:`aesop.core.detect.identify`.
All the real signature-matching logic lives in :mod:`aesop.core.detect`; this
module only:

1. exposes a tiny pure helper, :func:`quick_stats`, that summarises a blob's
   shape (length, printable ratio, entropy, index of coincidence); and
2. presents the ranked :class:`~aesop.core.detect.Guess` list plus that stats
   line through an :class:`aesop.ui.Output`.

Keeping the analysis in ``core.detect`` means the same reasoning powers both
this command and the ``auto`` solver.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..registry import command, io_args
from ..core import io
from ..core.detect import identify, Guess
from ..core.score import (
    shannon_entropy,
    index_of_coincidence,
    printable_ratio,
    clean_text,
)


# --------------------------------------------------------------------------- #
# Programmatic API
# --------------------------------------------------------------------------- #
def quick_stats(data: bytes) -> Dict[str, Any]:
    """Summarise the coarse shape of ``data`` for triage.

    Returns a dict with the four numbers a cryptanalyst eyeballs first:

    * ``length``    — number of bytes;
    * ``letters``   — how many are ASCII letters (classical ciphers are ~all letters);
    * ``printable`` — fraction of printable-ASCII bytes (0..1);
    * ``entropy``   — Shannon entropy in bits/byte (≈8 ⇒ random/encrypted);
    * ``ic``        — index of coincidence (≈0.066 English, ≈0.038 random).

    Pure and importable — no printing, no I/O.
    """
    text = data.decode("latin-1")
    return {
        "length": len(data),
        "letters": len(clean_text(text)),
        "printable": printable_ratio(data),
        "entropy": shannon_entropy(data),
        "ic": index_of_coincidence(text),
    }


def top_guess(data: bytes) -> Guess:
    """Return the single highest-confidence hypothesis for ``data``."""
    return identify(data)[0]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "identify",
    group="analysis",
    summary="Guess what a blob is — encoding, cipher, hash or plaintext",
    manual="identify",
    aliases=["id", "detect"],
    args=io_args(
        positional="data",
        positional_help="the mystery blob to fingerprint (or pipe via stdin / use --file)",
    ),
    examples=[
        "aesop identify 'V2FrZSB1cCwgTmVvIQ=='",
        "echo 'Wkh txlfn eurzq ira' | aesop identify",
        "aesop identify -f mystery.bin",
        "aesop identify 5d41402abc4b2a76b9719d911017c592   # an md5?",
    ],
    description="""
        The first tool to reach for when you have no idea what you are looking
        at.  ``identify`` fingerprints the input against a battery of signatures
        — entropy, index of coincidence, character set and structure — and
        prints ranked hypotheses, each with a plain-English reason and the exact
        AESOP command to try next.  It analyses the input *literally* (it does
        not silently decode base64/hex first — that's the whole point), so pipe
        raw ciphertext, a suspicious token, or a binary file straight in.
    """,
)
def cmd_identify(args, out) -> int:
    inp = _load_literal(args)
    data = inp.data
    if not data:
        out.error("no input to identify")
        return 2

    guesses = identify(data)

    # PRIMARY, pipe-friendly result: the best guess's label on its own line.
    out.raw(guesses[0].label)

    # Secondary/diagnostic: the ranked table and a shape summary.
    out.print()
    out.table(
        ["what", "kind", "conf", "why", "try"],
        [tuple(g) for g in guesses],
        title="ranked hypotheses (best first)",
    )

    st = quick_stats(data)
    out.print()
    out.keyval(
        [
            ("length", f"{st['length']} bytes ({st['letters']} letters)"),
            ("printable", f"{st['printable']:.0%}"),
            ("entropy", f"{st['entropy']:.3f} bits/byte"),
            ("index of coincidence", f"{st['ic']:.4f}"),
        ],
        title="input stats",
    )
    if guesses[0].suggest and guesses[0].suggest != "(nothing to do)":
        out.hint(f"next: {guesses[0].suggest}")
    return 0


# --------------------------------------------------------------------------- #
# Shared input handling for the analysis commands
# --------------------------------------------------------------------------- #
def _load_literal(args):
    """Load input for *analysis*: the literal bytes, never auto-decoded.

    Triage commands must see exactly what the user handed over — otherwise
    ``identify`` on a base64 string would helpfully decode it and then fail to
    notice it was base64.  So by default we read the raw bytes (``binary=True``
    keeps high bytes intact over stdin/files, ``encoding='raw'`` stops a literal
    argument being sniffed and decoded).  An explicit ``-e`` still forces a
    decode first, for callers who want to analyse the *decoded* payload.
    """
    ue = getattr(args, "in_encoding", "auto") or "auto"
    if ue != "auto":
        return io.load(args, encoding=ue)
    return io.load(args, binary=True, encoding="raw")

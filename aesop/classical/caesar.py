"""
aesop.classical.caesar — Caesar / ROT-n shift ciphers.

This module is the canonical example of an AESOP technique module.  It has two
halves that every module should keep separate:

1. A **programmatic API** (pure functions on ``str``/``bytes``) that is unit
   tested and importable — ``shift``, ``brute_force``, ``solve``.
2. A **command handler** wired into the CLI via the :func:`aesop.registry.command`
   decorator, which only does argument marshalling, I/O and presentation.

Keeping them apart means the algorithms stay testable and reusable while the CLI
stays thin.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import score_text, chi_squared, clean_text

A = ord("A")


# --------------------------------------------------------------------------- #
# Programmatic API
# --------------------------------------------------------------------------- #
def shift(text: str, n: int) -> str:
    """Shift every letter of ``text`` by ``n`` (preserving case & non-letters)."""
    n %= 26
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + n) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - A + n) % 26 + A))
        else:
            out.append(ch)
    return "".join(out)


def brute_force(text: str) -> List[Tuple[int, str, float]]:
    """Return all 26 shifts as ``(shift, plaintext, score)``, unranked."""
    return [(n, shift(text, n), score_text(shift(text, n))) for n in range(26)]


def solve(text: str, top: int = 3) -> List[Tuple[int, str, float]]:
    """Rank the 26 shifts by English-likeness; return the best ``top``.

    Uses quadgram scoring, which reliably lifts the true plaintext to rank 1 for
    any input of a dozen or more letters.
    """
    ranked = sorted(brute_force(text), key=lambda t: t[2], reverse=True)
    return ranked[:top]


def best_shift_by_chi2(text: str) -> int:
    """Fast single-answer solve using chi-squared (good for short ciphertext)."""
    return min(range(26), key=lambda n: chi_squared(shift(text, n)))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "caesar",
    group="classical",
    summary="Break or apply a Caesar / ROT-n shift cipher",
    manual="caesar",
    aliases=["rot", "shift"],
    args=io_args(positional="text", positional_help="the ciphertext to break (or plaintext to encode)") + [
        arg("-n --shift", "known shift amount; omit to auto-solve", type=int),
        arg("--encode", "encode/encrypt with --shift instead of breaking", action="store_true"),
        arg("--all", "show all 26 shifts (a ROT table), ranked", action="store_true"),
        arg("--top", "how many candidates to show when auto-solving", type=int, default=3),
    ],
    examples=[
        "aesop caesar 'Wkh txlfn eurzq ir{'",
        "aesop caesar --encode -n 13 'Attack at dawn'   # ROT13",
        "aesop caesar --all 'Uryyb Jbeyq'",
        "echo 'Fdhvdu flskhu' | aesop caesar",
    ],
    description="""
        Caesar shifts each letter by a fixed amount; ROT13 is the shift-13
        special case.  With --shift the transform is applied directly; without
        it, AESOP tries all 26 shifts and ranks them by how English-like the
        result looks (quadgram scoring), so the plaintext usually lands first.
    """,
)
def cmd_caesar(args, out) -> int:
    # Encoding takes plaintext: never sniff (prose can be valid base64/hex).
    inp = io.load(args, encoding="raw" if args.encode else None)
    text = inp.text

    if args.encode:
        n = args.shift if args.shift is not None else 3
        out.raw(shift(text, n))
        return 0

    if args.shift is not None:
        out.raw(shift(text, args.shift))
        return 0

    if args.all:
        rows = sorted(brute_force(text), key=lambda t: t[2], reverse=True)
        out.table(
            ["shift", "score", "plaintext"],
            [(n, f"{s:8.1f}", _preview(pt)) for n, pt, s in rows],
            title="all 26 shifts (best first)",
        )
        return 0

    ranked = solve(text, top=max(1, args.top))
    best_n, best_pt, best_score = ranked[0]
    out.success(f"best guess — shift {best_n} (ROT{best_n})")
    out.raw(best_pt)
    if len(ranked) > 1:
        out.print()
        out.table(
            ["rank", "shift", "score", "plaintext"],
            [(i + 1, n, f"{s:8.1f}", _preview(pt)) for i, (n, pt, s) in enumerate(ranked)],
            title="candidates",
        )
    return 0


def _preview(text: str, width: int = 60) -> str:
    t = text.replace("\n", " ")
    return t if len(t) <= width else t[: width - 1] + "…"

"""
aesop.classical.affine — the Affine cipher (E(x) = a·x + b mod 26).

The Affine cipher generalises Caesar: instead of only *adding* a constant, it
first *multiplies* each letter's index by a key ``a`` (which must be coprime
with 26 so the map is invertible) and then adds a shift ``b``.  Caesar is the
special case ``a = 1``; Atbash is ``a = 25, b = 25``.

Like every AESOP technique module this file keeps two halves apart:

1. A **programmatic API** (pure functions on ``str``) that is importable and
   unit-testable — :func:`encrypt`, :func:`decrypt`, :func:`brute_force`,
   :func:`solve`, :func:`best_by_chi2`.
2. A **command handler** wired into the CLI via :func:`aesop.registry.command`,
   which only marshals arguments, loads input and presents results.

The keyspace is tiny — 12 legal values of ``a`` times 26 values of ``b`` = 312
keys (311 non-trivial) — so breaking it is an exhaustive search ranked by an
English-likeness score, exactly as with Caesar.
"""
from __future__ import annotations

import math
from typing import List, Tuple

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import score_text, chi_squared
from ..core.util import modinv

A = ord("A")
M = 26

# The 12 multipliers coprime with 26 (26 = 2·13, so all odd numbers except 13).
COPRIME_WITH_26: List[int] = [a for a in range(1, M) if math.gcd(a, M) == 1]

Key = Tuple[int, int]


# --------------------------------------------------------------------------- #
# Programmatic API
# --------------------------------------------------------------------------- #
def _check_a(a: int) -> None:
    """Raise ``ValueError`` unless ``a`` is a legal (invertible) multiplier."""
    if math.gcd(a % M, M) != 1:
        raise ValueError(
            f"multiplier a={a} is not coprime with 26; "
            f"choose one of {COPRIME_WITH_26}"
        )


def encrypt(text: str, a: int, b: int) -> str:
    """Affine-encrypt ``text``: each letter x → (a·x + b) mod 26.

    Preserves case and passes non-letters through unchanged.  ``a`` must be
    coprime with 26 (see :data:`COPRIME_WITH_26`) or ``ValueError`` is raised.
    """
    _check_a(a)
    a %= M
    b %= M
    out: List[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            x = ord(ch) - ord("a")
            out.append(chr((a * x + b) % M + ord("a")))
        elif "A" <= ch <= "Z":
            x = ord(ch) - A
            out.append(chr((a * x + b) % M + A))
        else:
            out.append(ch)
    return "".join(out)


def decrypt(text: str, a: int, b: int) -> str:
    """Affine-decrypt ``text``: each letter y → a⁻¹·(y − b) mod 26.

    The inverse of :func:`encrypt` with the same key; raises ``ValueError`` if
    ``a`` has no inverse modulo 26.
    """
    _check_a(a)
    a_inv = modinv(a % M, M)
    b %= M
    out: List[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            y = ord(ch) - ord("a")
            out.append(chr((a_inv * (y - b)) % M + ord("a")))
        elif "A" <= ch <= "Z":
            y = ord(ch) - A
            out.append(chr((a_inv * (y - b)) % M + A))
        else:
            out.append(ch)
    return "".join(out)


def brute_force(text: str) -> List[Tuple[Key, str, float]]:
    """Decrypt ``text`` under all 312 keys; return ``((a, b), plaintext, score)``.

    Unranked; iterate ``a`` over the 12 legal multipliers and ``b`` over 0–25.
    """
    results: List[Tuple[Key, str, float]] = []
    for a in COPRIME_WITH_26:
        a_inv = modinv(a, M)
        for b in range(M):
            pt = _decrypt_fast(text, a_inv, b)
            results.append(((a, b), pt, score_text(pt)))
    return results


def _decrypt_fast(text: str, a_inv: int, b: int) -> str:
    """Inner decrypt loop that reuses a precomputed ``a_inv`` (hot path)."""
    out: List[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            y = ord(ch) - ord("a")
            out.append(chr((a_inv * (y - b)) % M + ord("a")))
        elif "A" <= ch <= "Z":
            y = ord(ch) - A
            out.append(chr((a_inv * (y - b)) % M + A))
        else:
            out.append(ch)
    return "".join(out)


def solve(text: str, top: int = 3) -> List[Tuple[Key, str, float]]:
    """Rank all 312 keys by English-likeness; return the best ``top``.

    Uses quadgram scoring (see :mod:`aesop.core.score`), which reliably lifts the
    true plaintext to rank 1 for any input of roughly a dozen or more letters.
    """
    ranked = sorted(brute_force(text), key=lambda t: t[2], reverse=True)
    return ranked[: max(1, top)]


def best_by_chi2(text: str) -> Key:
    """Fast single-answer solve using chi-squared (good for short ciphertext).

    Returns the ``(a, b)`` whose decryption best matches English letter
    frequencies.  Needs no full-language model, so it degrades far more
    gracefully than quadgrams on a handful of letters.
    """
    best: Key = (1, 0)
    best_chi = float("inf")
    for a in COPRIME_WITH_26:
        a_inv = modinv(a, M)
        for b in range(M):
            chi = chi_squared(_decrypt_fast(text, a_inv, b))
            if chi < best_chi:
                best_chi = chi
                best = (a, b)
    return best


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "affine",
    group="classical",
    summary="Break or apply an Affine cipher, E(x) = a·x + b (mod 26)",
    manual="affine",
    args=io_args(positional="text", positional_help="the ciphertext to break (or plaintext to encode)") + [
        arg("-a", "known multiplier a (must be coprime with 26)", type=int),
        arg("-b", "known additive shift b (0–25)", type=int),
        arg("--encode", "encode/encrypt with -a/-b instead of breaking", action="store_true"),
        arg("--chi2", "solve short text with chi-squared instead of quadgrams", action="store_true"),
        arg("--top", "how many candidates to show when auto-solving", type=int, default=3),
    ],
    examples=[
        "aesop affine 'Izzisg iz xiov, zrc hat wu oizsrwvm zrc spao.'",
        "aesop affine --encode -a 5 -b 8 'Attack at dawn'",
        "aesop affine -a 5 -b 8 'Izzisg iz xiov'   # decode a known key",
        "echo 'Izzisg iz xiov' | aesop affine --chi2",
    ],
    description="""
        The Affine cipher maps each letter x to (a·x + b) mod 26, where a is one
        of the 12 values coprime with 26 (so the map inverts) and b is any shift
        0–25.  Caesar is the special case a=1.  With -a/-b the transform is
        applied directly (add --encode to encrypt); without a key AESOP tries all
        312 keys and ranks them by how English-like the result looks (quadgram
        scoring), so the plaintext and its (a, b) usually land first.  For very
        short ciphertext, --chi2 switches to frequency matching.
    """,
)
def cmd_affine(args, out) -> int:
    # Encoding takes plaintext: never sniff (prose can be valid base64/hex).
    inp = io.load(args, encoding="raw" if args.encode else None)
    text = inp.text

    # --- Direct transform when a key (or --encode) is supplied ------------- #
    if args.encode or args.a is not None or args.b is not None:
        # Classic textbook defaults (Wikipedia's a=5, b=8) when a part is omitted.
        a = args.a if args.a is not None else 5
        b = args.b if args.b is not None else 8
        if math.gcd(a % M, M) != 1:
            out.error(f"multiplier a={a} is not coprime with 26")
            out.hint(f"valid values of a: {', '.join(map(str, COPRIME_WITH_26))}")
            return 1
        out.raw(encrypt(text, a, b) if args.encode else decrypt(text, a, b))
        return 0

    # --- Auto-solve -------------------------------------------------------- #
    if args.chi2:
        a, b = best_by_chi2(text)
        pt = decrypt(text, a, b)
        out.success(f"best guess (chi²) — key a={a}, b={b}")
        out.raw(pt)
        return 0

    ranked = solve(text, top=max(1, args.top))
    (best_a, best_b), best_pt, best_score = ranked[0]
    out.success(f"best guess — key a={best_a}, b={best_b}")
    out.raw(best_pt)
    if len(ranked) > 1:
        out.print()
        out.table(
            ["rank", "a", "b", "score", "plaintext"],
            [(i + 1, a, b, f"{s:8.1f}", _preview(pt))
             for i, ((a, b), pt, s) in enumerate(ranked)],
            title="candidates",
        )
    return 0


def _preview(text: str, width: int = 60) -> str:
    t = text.replace("\n", " ")
    return t if len(t) <= width else t[: width - 1] + "…"

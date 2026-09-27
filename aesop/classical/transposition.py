"""
aesop.classical.transposition — transposition ciphers (order permuted, letters kept).

A transposition cipher never substitutes a letter; it only *rearranges* them.
The letter histogram of the ciphertext is therefore identical to the plaintext's
— the Index of Coincidence stays English-like (~0.066) — which is exactly the
tell that separates a transposition from a substitution cipher.

Two classic schemes live here:

* **Rail fence** — write the text in a zig-zag across ``rails`` lines, then read
  the lines top to bottom.
* **Columnar** — write the text into a grid row by row, then read the columns in
  an order dictated by a keyword (or an explicit digit permutation).

Like every AESOP module this file keeps two halves apart:

1. A **programmatic API** of pure functions on ``str`` — ``railfence_encrypt`` /
   ``railfence_decrypt`` / ``solve_railfence`` and ``columnar_encrypt`` /
   ``columnar_decrypt`` / ``solve_columnar`` — importable and unit-testable.
2. A thin **command handler** wired in with :func:`aesop.registry.command` that
   only marshals args, loads input and presents results through ``out``.
"""
from __future__ import annotations

import math
import re
from typing import Callable, List, Optional, Sequence, Tuple

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import clean_text, default_scorer


# --------------------------------------------------------------------------- #
# Rail fence
# --------------------------------------------------------------------------- #
def _rail_pattern(n: int, rails: int) -> List[int]:
    """The rail index visited by each of ``n`` successive characters (zig-zag)."""
    pattern: List[int] = []
    rail = 0
    direction = 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return pattern


def railfence_encrypt(text: str, rails: int) -> str:
    """Encrypt ``text`` with a rail-fence of ``rails`` lines.

    Every character (letters, spaces, punctuation) is placed on the zig-zag and
    the lines are concatenated top to bottom.  ``rails < 2`` is a no-op.
    """
    if rails < 2 or len(text) <= rails:
        return text
    fence: List[List[str]] = [[] for _ in range(rails)]
    for ch, r in zip(text, _rail_pattern(len(text), rails)):
        fence[r].append(ch)
    return "".join("".join(row) for row in fence)


def railfence_decrypt(text: str, rails: int) -> str:
    """Invert :func:`railfence_encrypt` for a known number of ``rails``."""
    if rails < 2 or len(text) <= rails:
        return text
    n = len(text)
    pattern = _rail_pattern(n, rails)
    counts = [pattern.count(r) for r in range(rails)]

    # Slice the ciphertext back into the individual rails.
    rows: List[List[str]] = []
    pos = 0
    for c in counts:
        rows.append(list(text[pos:pos + c]))
        pos += c

    # Walk the zig-zag again, pulling one char off each rail in turn.
    idx = [0] * rails
    out: List[str] = []
    for r in pattern:
        out.append(rows[r][idx[r]])
        idx[r] += 1
    return "".join(out)


def solve_railfence(
    text: str,
    max_rails: int = 15,
    top: int = 3,
) -> List[Tuple[int, str, float]]:
    """Brute-force the rail count and rank by English-likeness.

    Returns up to ``top`` ``(rails, plaintext, score)`` tuples, best first.
    Quadgram scoring floats the true plaintext to rank 1 for any reasonable
    length of ciphertext.
    """
    scorer = default_scorer()
    n = len(text)
    hi = max(2, min(max_rails, n - 1))
    results = [
        (rails, railfence_decrypt(text, rails), scorer.score(railfence_decrypt(text, rails)))
        for rails in range(2, hi + 1)
    ]
    results.sort(key=lambda t: t[2], reverse=True)
    return results[:max(1, top)]


# --------------------------------------------------------------------------- #
# Columnar
# --------------------------------------------------------------------------- #
def _rank(letters: Sequence[str]) -> List[int]:
    """Alphabetical rank (0-based) of each letter, ties broken left-to-right."""
    order = sorted(range(len(letters)), key=lambda i: (letters[i], i))
    ranks = [0] * len(letters)
    for r, i in enumerate(order):
        ranks[i] = r
    return ranks


def parse_key(key: str) -> List[int]:
    """Turn a user key into a column *read order*.

    Accepts either a keyword (``"ZEBRA"`` → columns read in the alphabetical
    rank of their letters) or an explicit numeric permutation (``"31542"`` or
    ``"3 1 5 4 2"`` / ``"3,1,5,4,2"``).  The returned list ``order`` gives, for
    read position ``i``, the grid-column index ``order[i]`` to emit.
    """
    key = key.strip()
    if not key:
        raise ValueError("empty transposition key")

    compact = re.sub(r"[\s,]+", "", key)
    if compact.isdigit():
        # Numeric permutation.  Multi-digit columns must be separated.
        if re.search(r"[\s,]", key):
            priorities = [int(tok) for tok in re.split(r"[\s,]+", key) if tok]
        else:
            priorities = [int(c) for c in compact]
    else:
        letters = [c for c in key.upper() if c.isalpha()]
        if not letters:
            raise ValueError(f"key {key!r} has no letters or digits")
        priorities = _rank(letters)

    if len(priorities) < 2:
        raise ValueError("a columnar key needs at least 2 columns")
    if len(set(priorities)) != len(priorities):
        raise ValueError(f"key {key!r} has repeated column numbers")

    # Read columns in ascending priority; stable on ties (there are none).
    return sorted(range(len(priorities)), key=lambda i: (priorities[i], i))


def _order_to_key(order: Sequence[int]) -> str:
    """Render a read order back as a 1-based digit key that ``parse_key`` accepts."""
    priorities = [0] * len(order)
    for pos, col in enumerate(order):
        priorities[col] = pos + 1
    if len(order) <= 9:
        return "".join(str(p) for p in priorities)
    return "-".join(str(p) for p in priorities)


def _encrypt_with_order(text: str, order: Sequence[int]) -> str:
    """Columnar encrypt given a resolved read ``order`` (irregular last row ok)."""
    cols = len(order)
    rows = math.ceil(len(text) / cols) if text else 0
    grid = [text[r * cols:(r + 1) * cols] for r in range(rows)]
    out: List[str] = []
    for col in order:
        for r in range(rows):
            if col < len(grid[r]):
                out.append(grid[r][col])
    return "".join(out)


def _decrypt_with_order(cipher: str, order: Sequence[int]) -> str:
    """Invert :func:`_encrypt_with_order` for a resolved read ``order``."""
    cols = len(order)
    n = len(cipher)
    if n == 0:
        return ""
    rows = math.ceil(n / cols)
    n_last = n - (rows - 1) * cols          # filled cells in the final row
    col_len = [rows if c < n_last else rows - 1 for c in range(cols)]

    # Cut the ciphertext into columns following the read order.
    col_data: dict = {}
    pos = 0
    for col in order:
        col_data[col] = cipher[pos:pos + col_len[col]]
        pos += col_len[col]

    # Rebuild row by row.
    idx = [0] * cols
    out: List[str] = []
    for r in range(rows):
        for c in range(cols):
            if r < col_len[c]:
                out.append(col_data[c][idx[c]])
                idx[c] += 1
    return "".join(out)


def columnar_encrypt(text: str, key: str) -> str:
    """Columnar-transposition encrypt ``text`` under ``key`` (keyword or digits)."""
    return _encrypt_with_order(text, parse_key(key))


def columnar_decrypt(text: str, key: str) -> str:
    """Columnar-transposition decrypt ``text`` under a known ``key``."""
    return _decrypt_with_order(text, parse_key(key))


def solve_columnar(
    text: str,
    max_cols: int = 8,
    top: int = 3,
    perm_cap: int = 5040,
    on_cap: Optional[Callable[[str], None]] = None,
) -> List[Tuple[str, int, str, float]]:
    """Brute-force column count and permutation, ranked by English-likeness.

    Cleans ``text`` to letters (columnar ciphertext is normally letters only),
    then for each column count from 2 upward enumerates every permutation and
    scores the decryption with quadgrams.  Column counts whose factorial exceeds
    ``perm_cap`` are skipped; when ``on_cap`` is supplied it is called with a
    human note describing what was left out (the CLI passes ``out.hint``).

    Returns up to ``top`` ``(key, cols, plaintext, score)`` tuples, best first,
    where ``key`` is a digit permutation you can feed back to ``--key``.
    """
    from itertools import permutations

    clean = clean_text(text)
    scorer = default_scorer()
    results: List[Tuple[str, int, str, float]] = []

    for cols in range(2, max_cols + 1):
        if cols >= len(clean):
            break
        if math.factorial(cols) > perm_cap:
            if on_cap is not None:
                on_cap(
                    f"capped: {cols}!={math.factorial(cols)} permutations exceeds "
                    f"perm_cap={perm_cap}; skipping {cols}+ columns "
                    f"(raise --max-cols / perm_cap to search wider)"
                )
            break
        for perm in permutations(range(cols)):
            pt = _decrypt_with_order(clean, perm)
            results.append((_order_to_key(perm), cols, pt, scorer.score(pt)))

    results.sort(key=lambda t: t[3], reverse=True)
    return results[:max(1, top)]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "transposition",
    group="classical",
    summary="Break or apply rail-fence & columnar transposition ciphers",
    manual="transposition",
    aliases=["transpose"],
    args=io_args(
        positional="text",
        positional_help="the ciphertext to break (or plaintext to encode)",
    ) + [
        arg(
            "-t --type",
            "which scheme: rail, columnar, or auto (try both, best wins)",
            choices=["rail", "columnar", "auto"],
            default="auto",
        ),
        arg("-r --rails", "rail-fence rail count (known key, or to encode)", type=int),
        arg("-k --key", "columnar key: keyword or digit permutation (e.g. ZEBRA / 31542)"),
        arg("--encode", "encrypt with --rails/--key instead of breaking", action="store_true"),
        arg("--top", "how many candidates to show when auto-solving", type=int, default=3),
        arg("--max-cols", "largest column count to try when breaking columnar", type=int, default=8),
        arg("--max-rails", "largest rail count to try when breaking rail-fence", type=int, default=15),
    ],
    examples=[
        "aesop transposition 'WNSEHSSWRLEEOALO'                 # auto-solve",
        "aesop transposition --encode -t rail -r 3 'we are discovered flee at once'",
        "aesop transposition --encode -t columnar -k ZEBRA 'wearediscoveredfleeatonce'",
        "aesop transposition -t columnar -k ZEBRA 'EODAEASRENEIELORCEECWDVFT'",
    ],
    description="""
        A transposition cipher scrambles letter *order*, never identity, so the
        ciphertext keeps an English letter frequency (high IC).  This command
        handles the two classic schemes.  RAIL-FENCE writes the text in a
        zig-zag across N lines; COLUMNAR writes it into a grid and reads the
        columns in a keyed order.  Give --rails or --key to apply a known key
        (add --encode to encrypt); give neither and AESOP brute-forces the key
        space and ranks candidates by quadgram score, floating the plaintext to
        the top.  With --type auto (the default) it tries both schemes and
        returns the single best-scoring decryption.
    """,
)
def cmd_transposition(args, out) -> int:
    # Encoding takes plaintext verbatim; breaking may autodetect hex/base64.
    inp = io.load(args, encoding="raw" if args.encode else None)
    # A transposition permutes *every* character, so a stray trailing newline
    # (added by pipes/echo/out.raw) would shift the whole grid.  Strip the
    # surrounding whitespace of the block; interior spaces are kept & permuted.
    text = inp.text.strip()
    ttype = args.type

    # ---- encode ----------------------------------------------------------- #
    if args.encode:
        if ttype == "columnar":
            if not args.key:
                out.error("columnar --encode needs --key")
                return 2
            out.raw(columnar_encrypt(text, args.key))
        elif ttype == "rail":
            out.raw(railfence_encrypt(text, args.rails if args.rails is not None else 3))
        else:  # auto: infer from whichever key was supplied
            if args.key:
                out.raw(columnar_encrypt(text, args.key))
            else:
                out.raw(railfence_encrypt(text, args.rails if args.rails is not None else 3))
        return 0

    # ---- decode with a known key ------------------------------------------ #
    if args.key is not None and ttype in ("columnar", "auto"):
        out.raw(columnar_decrypt(text, args.key))
        return 0
    if args.rails is not None and ttype in ("rail", "auto"):
        out.raw(railfence_decrypt(text, args.rails))
        return 0

    # ---- auto-solve ------------------------------------------------------- #
    candidates: List[Tuple[str, str, str, float]] = []  # (scheme, param, plaintext, score)

    if ttype in ("rail", "auto"):
        for rails, pt, sc in solve_railfence(text, max_rails=max(2, args.max_rails), top=max(1, args.top)):
            candidates.append(("rail", f"rails={rails}", pt, sc))

    if ttype in ("columnar", "auto"):
        for key, cols, pt, sc in solve_columnar(
            text, max_cols=max(2, args.max_cols), top=max(1, args.top), on_cap=out.hint
        ):
            candidates.append(("columnar", f"key={key} (cols={cols})", pt, sc))

    if not candidates:
        out.error("nothing to solve — input too short for any tried key")
        return 1

    candidates.sort(key=lambda c: c[3], reverse=True)
    best_scheme, best_param, best_pt, best_score = candidates[0]
    out.success(f"best guess — {best_scheme} transposition, {best_param}")
    out.raw(best_pt)

    if len(candidates) > 1:
        out.print()
        out.table(
            ["rank", "scheme", "key", "score", "plaintext"],
            [
                (i + 1, scheme, param, f"{sc:9.1f}", _preview(pt))
                for i, (scheme, param, pt, sc) in enumerate(candidates[:max(1, args.top)])
            ],
            title="candidates (best first)",
        )
    return 0


def _preview(text: str, width: int = 50) -> str:
    t = text.replace("\n", " ")
    return t if len(t) <= width else t[: width - 1] + "…"

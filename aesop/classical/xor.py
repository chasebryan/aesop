"""
aesop.classical.xor — single-byte and repeating-key XOR (the cryptopals classics).

XOR is the atom of symmetric crypto: fast, involutive (``a ^ k ^ k == a``), and
utterly insecure when the key is short or reused.  Two flavours dominate CTFs
and challenge sets:

* **Single-byte XOR** — every plaintext byte is XORed with the same byte ``k``.
  There are only 256 keys, so we try them all and keep the most English-like.
* **Repeating-key (Vigenère) XOR** — the key is a short byte string cycled over
  the message.  We recover the key length from the *normalised Hamming distance*
  between blocks, transpose the ciphertext into single-byte columns, and break
  each column independently — the celebrated cryptopals Set-1 attack.

Like every AESOP technique module this splits cleanly into

1. a pure, importable **programmatic API** on ``bytes`` (no printing), and
2. a thin **CLI handler** that only marshals arguments, loads input and presents
   results via the shared :class:`aesop.ui.Output`.
"""
from __future__ import annotations

import re
from typing import List, Tuple, Union

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import default_scorer, printable_ratio, ENGLISH_FREQ

BytesLike = Union[bytes, bytearray, str]

# Pre-computed population counts (bits set) for every byte value.
_POPCOUNT = bytes(bin(i).count("1") for i in range(256))

# Per-byte English fitness weights, used to break short single-byte columns
# where a running-text model has too little to chew on.  Common letters and the
# space carry their real English frequencies (space highest, as in prose); other
# printable bytes get a small penalty; control bytes a large one.  Summed and
# normalised over a candidate, this cleanly separates plaintext columns from the
# symbol/control soup a wrong key produces.
_CHAR_WEIGHT: List[float] = [-8.0] * 256
for _b in range(256):
    if _b in (9, 10, 13):        # tab / newline / carriage-return
        _CHAR_WEIGHT[_b] = -1.0
    elif 32 <= _b < 127:         # other printable ASCII (punctuation, digits)
        _CHAR_WEIGHT[_b] = -1.5
_CHAR_WEIGHT[32] = 13.0          # space — the most common character in English
for _ch, _f in ENGLISH_FREQ.items():
    _CHAR_WEIGHT[ord(_ch)] = _f
    _CHAR_WEIGHT[ord(_ch.lower())] = _f
del _b, _ch, _f


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _as_bytes(x: BytesLike) -> bytes:
    """Coerce ``str``/``bytearray``/``bytes`` to ``bytes`` (str via UTF-8)."""
    if isinstance(x, str):
        return x.encode("utf-8")
    return bytes(x)


def english_score(data: bytes) -> float:
    """How English-like a candidate looks (higher is better).

    Tuned for the hard case — breaking a short single-byte column, which is a
    *subsequence* of English rather than running prose.  It blends three
    complementary signals:

    * **character frequency** (:data:`_CHAR_WEIGHT`) — the dominant cue: rewards
      spaces and common letters, penalises the symbols and control bytes a wrong
      key produces;
    * **printable ratio** — a broad guard against binary garbage;
    * **quadgram log-probability** (:mod:`aesop.core.score`) — a light refinement
      once the candidate already looks like text.

    To choose between whole recovered *messages* (e.g. rival key lengths) prefer
    :func:`running_text_score`, which the quadgram model handles better.
    """
    if not data:
        return -1e9
    n = len(data)
    freq = sum(_CHAR_WEIGHT[b] for b in data) / n
    printable = printable_ratio(data)
    quad = default_scorer().score_normalized(data.decode("latin-1"))
    return freq + 6.0 * printable + 0.5 * quad


def running_text_score(data: bytes) -> float:
    """Fitness of a whole candidate message (higher is better).

    Used to pick between fully recovered plaintexts (rival key lengths, or
    single-byte vs repeating).  It leans on *per-quadgram* log-probability, which
    rewards genuine English letter order, but keeps the character-frequency and
    printable terms so a wrong key that produces symbol/punctuation soup cannot
    win merely because stripping its non-letters leaves fewer quadgrams to sum.
    """
    if not data:
        return -1e9
    n = len(data)
    freq = sum(_CHAR_WEIGHT[b] for b in data) / n
    printable = printable_ratio(data)
    quad = default_scorer().score_normalized(data.decode("latin-1"))
    return 3.0 * quad + freq + 6.0 * printable


# --------------------------------------------------------------------------- #
# Programmatic API
# --------------------------------------------------------------------------- #
def xor_bytes(data: BytesLike, key: Union[BytesLike, int]) -> bytes:
    """Repeating-key XOR of ``data`` with ``key`` (also covers the single-byte
    and one-time-pad cases).  ``key`` may be ``bytes``, ``str`` or an ``int``
    (0-255).  XOR is its own inverse, so this both encrypts and decrypts."""
    data = _as_bytes(data)
    if isinstance(key, int):
        key = bytes([key & 0xFF])
    key = _as_bytes(key)
    if not key:
        raise ValueError("key must be non-empty")
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def break_single_byte(data: BytesLike) -> List[Tuple[int, bytes, float]]:
    """Try all 256 single-byte keys; return ``(keybyte, plaintext, score)``
    ranked best-first by :func:`english_score`."""
    data = _as_bytes(data)
    scored = []
    for k in range(256):
        pt = bytes(b ^ k for b in data)
        scored.append((k, pt, english_score(pt)))
    scored.sort(key=lambda t: t[2], reverse=True)
    return scored


def hamming(a: BytesLike, b: BytesLike) -> int:
    """Bit-level Hamming distance (number of differing bits).

    For equal-length inputs (the case in keysize detection) this is the classic
    edit distance in bits; mismatched tails count every bit of the surplus.
    """
    a = _as_bytes(a)
    b = _as_bytes(b)
    n = min(len(a), len(b))
    dist = sum(_POPCOUNT[x ^ y] for x, y in zip(a, b))
    for x in a[n:]:
        dist += _POPCOUNT[x]
    for x in b[n:]:
        dist += _POPCOUNT[x]
    return dist


def _keysize_scores(data: bytes, lo: int, hi: int, min_blocks: int,
                    block_cap: int = 24) -> List[Tuple[int, float]]:
    """Normalised all-pairs Hamming score per key length (helper)."""
    from itertools import combinations

    ranked: List[Tuple[int, float]] = []
    for k in range(max(2, lo), hi + 1):
        nblocks = len(data) // k
        if nblocks < max(2, min_blocks):
            continue
        # Averaging over *all* block pairs (not just neighbours) sharply reduces
        # the noise that otherwise sinks the true length on short ciphertexts.
        # When there are many blocks, sample them spread across the whole input
        # (not just a prefix) so short and long key lengths are judged fairly.
        if nblocks <= block_cap:
            idx = range(nblocks)
        else:
            idx = [i * nblocks // block_cap for i in range(block_cap)]
        blocks = [data[i * k:(i + 1) * k] for i in idx]
        dists = [hamming(a, b) for a, b in combinations(blocks, 2)]
        ranked.append((k, (sum(dists) / len(dists)) / k))
    ranked.sort(key=lambda t: t[1])
    return ranked


def guess_keysize(data: BytesLike, lo: int = 2, hi: int = 40) -> List[Tuple[int, float]]:
    """Rank candidate key lengths by *normalised* average Hamming distance.

    For each key length ``k`` we slice the ciphertext into ``k``-byte blocks and
    average the Hamming distance between block pairs, then divide by ``k``.  The
    true key length (and its multiples) minimises this figure because those
    blocks were produced by the *same* key bytes, so their XOR reveals only the
    plaintext-vs-plaintext difference (~2.6-3.3 bits/byte for English) rather
    than the ~4.0 of unrelated bytes.  Key lengths with too few blocks to measure
    reliably are dropped when enough well-sampled candidates remain.  Returns
    ``(keysize, score)`` best-first.
    """
    data = _as_bytes(data)
    hi = min(hi, len(data) // 2)
    if hi < 2:
        return []
    # Prefer well-sampled key lengths; relax the block requirement only if that
    # would leave us with nothing to rank.
    ranked = _keysize_scores(data, lo, hi, min_blocks=4)
    if not ranked:
        ranked = _keysize_scores(data, lo, hi, min_blocks=2)
    return ranked


def _minimize_period(key: bytes) -> bytes:
    """Collapse a key that is itself a repetition (``KEYKEY`` -> ``KEY``)."""
    n = len(key)
    for p in range(1, n):
        if n % p == 0 and key == key[:p] * (n // p):
            return key[:p]
    return key


def solve_keysize(data: bytes, keysize: int) -> bytes:
    """Recover the key for a *known* key length by breaking each column."""
    data = _as_bytes(data)
    key = bytearray()
    for col in range(keysize):
        column = data[col::keysize]
        best_byte = break_single_byte(column)[0][0]
        key.append(best_byte)
    return bytes(key)


def break_repeating(data: BytesLike, tries: int = 6) -> Tuple[bytes, bytes]:
    """Break repeating-key XOR: ``(key, plaintext)``.

    Tries the top few candidate key lengths from :func:`guess_keysize`, solves
    each, and keeps whichever yields the most English-like plaintext; the winning
    key is then reduced to its minimal period so a 3-byte key is reported as 3
    bytes even when a multiple scored marginally better.
    """
    data = _as_bytes(data)
    ranked = guess_keysize(data)
    if not ranked:  # too short for block analysis — fall back to single byte
        k, pt, _ = break_single_byte(data)[0]
        return bytes([k]), pt

    # The true (fundamental) key length divides every multiple that scores well,
    # so we expand the top candidates with their divisors.  Smaller key lengths
    # give more bytes per column and thus break far more reliably, so this both
    # rescues a fundamental length the Hamming metric ranked below its multiples
    # and lets _minimize_period report the shortest key.
    candidates = set()
    for keysize, _ in ranked[:max(1, tries)]:
        candidates.add(keysize)
        for d in range(2, keysize):
            if keysize % d == 0:
                candidates.add(d)

    best: Tuple[bytes, bytes, float] | None = None
    for keysize in sorted(candidates):
        key = solve_keysize(data, keysize)
        pt = xor_bytes(data, key)
        sc = running_text_score(pt)
        if best is None or sc > best[2]:
            best = (key, pt, sc)
    assert best is not None
    key = _minimize_period(best[0])
    return key, xor_bytes(data, key)


def solve(data: BytesLike) -> Tuple[bytes, bytes]:
    """Auto-detect single-byte vs repeating-key XOR and recover ``(key, plaintext)``.

    Runs both attacks and keeps the higher-scoring plaintext, so the caller need
    not know which flavour of XOR produced the ciphertext.
    """
    data = _as_bytes(data)
    sk, spt, _ = break_single_byte(data)[0]
    rkey, rpt = break_repeating(data)
    if running_text_score(spt) >= running_text_score(rpt):
        return bytes([sk]), spt
    return rkey, rpt


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _parse_key(spec: str, key_type: str) -> bytes:
    if key_type == "hex":
        try:
            return bytes.fromhex(re.sub(r"\s", "", spec))
        except ValueError as exc:
            raise ValueError(f"--key is not valid hex: {exc}") from exc
    return spec.encode("utf-8")


def _render_bytes(data: bytes) -> str:
    """Primary-output rendering: text if it looks printable, else hex."""
    if printable_ratio(data) > 0.9:
        return data.decode("latin-1")
    return data.hex()


def _key_ascii(key: bytes) -> str:
    if all(32 <= b < 127 for b in key):
        return key.decode("ascii")
    return "(non-printable)"


@command(
    "xor",
    group="classical",
    summary="Break or apply single-byte / repeating-key XOR",
    manual="xor",
    aliases=["vxor", "xorcrack"],
    args=io_args(
        positional="text",
        positional_help="the XOR ciphertext to break (hex/base64/raw auto-detected)",
    ) + [
        arg("-k --key", "apply this key instead of solving (see --key-type)"),
        arg("--key-type", "how to read --key", choices=["ascii", "hex"], default="ascii"),
        arg("--single", "force single-byte mode when solving", action="store_true"),
        arg("--repeating", "force repeating-key mode when solving", action="store_true"),
        arg("--keysize", "force a repeating-key length (skip detection)", type=int),
        arg("--top", "how many single-byte candidates to show", type=int, default=3),
    ],
    examples=[
        "aesop xor 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736  # single-byte, hex",
        "aesop xor --key-type hex -k 4b4559 'Attack at dawn'   # apply a hex key",
        "aesop xor -k ICE --repeating cipher.b64",
        "cat secret.hex | aesop xor --top 5",
    ],
    description="""
        XOR analysis, the cryptopals way.  With --key the transform is applied
        directly (XOR encrypts and decrypts alike); without it AESOP auto-detects
        whether the ciphertext was made with a single byte or a repeating key and
        breaks it.  Single-byte mode tries all 256 keys; repeating mode recovers
        the key length from block Hamming distances, splits the ciphertext into
        single-byte columns, and solves each — reassembling the full key.  Input
        may be raw, hex or base64 (auto-detected); force it with -e.
    """,
)
def cmd_xor(args, out) -> int:
    # --- apply a known key (encrypt or decrypt; XOR is symmetric) ----------- #
    if args.key is not None:
        # Default to raw for the apply path so plaintext is never mis-sniffed;
        # honour an explicit -e (e.g. a hex ciphertext you are decrypting).
        enc = "raw" if getattr(args, "in_encoding", "auto") == "auto" else None
        inp = io.load(args, encoding=enc)
        try:
            key = _parse_key(args.key, args.key_type)
            result = xor_bytes(inp.data, key)
        except ValueError as exc:
            out.error(str(exc))
            return 1
        out.raw(_render_bytes(result))
        return 0

    # --- solve ------------------------------------------------------------- #
    inp = io.load(args)
    data = inp.data
    if not data:
        out.error("no input (give a value, --file, or pipe via stdin)")
        return 1

    if args.single and args.repeating:
        out.error("--single and --repeating are mutually exclusive")
        return 1

    # Single-byte, whether forced or when the data is too short to block-analyse.
    if args.single or (not args.repeating and args.keysize is None and len(data) < 4):
        ranked = break_single_byte(data)
        kb, pt, _ = ranked[0]
        out.success(f"key = {_key_ascii(bytes([kb]))}  ·  hex {kb:02x}  ·  single-byte")
        out.raw(_render_bytes(pt))
        _single_candidates(out, ranked, max(1, args.top))
        return 0

    if args.repeating or args.keysize is not None:
        if args.keysize is not None:
            key = solve_keysize(data, args.keysize)
            key = _minimize_period(key)
            pt = xor_bytes(data, key)
        else:
            key, pt = break_repeating(data)
        _report_key(out, key, pt)
        _keysize_table(out, data)
        return 0

    # Auto: run both and keep the more English-like result.
    key, pt = solve(data)
    _report_key(out, key, pt)
    if len(key) > 1:
        _keysize_table(out, data)
    else:
        _single_candidates(out, break_single_byte(data), max(1, args.top))
    return 0


def _report_key(out, key: bytes, pt: bytes) -> None:
    mode = "single-byte" if len(key) == 1 else f"repeating (keysize {len(key)})"
    out.success(f"key = {_key_ascii(key)}  ·  hex {key.hex()}  ·  {mode}")
    out.raw(_render_bytes(pt))


def _single_candidates(out, ranked: List[Tuple[int, bytes, float]], top: int) -> None:
    if top <= 1 or len(ranked) <= 1:
        return
    out.print()
    out.table(
        ["rank", "key", "hex", "score", "plaintext"],
        [
            (i + 1, _key_ascii(bytes([k])), f"{k:02x}", f"{s:7.2f}", _preview(pt))
            for i, (k, pt, s) in enumerate(ranked[:top])
        ],
        title="single-byte candidates",
    )


def _keysize_table(out, data: bytes, top: int = 5) -> None:
    ranked = guess_keysize(data)
    if not ranked:
        return
    out.print()
    out.table(
        ["keysize", "norm. hamming"],
        [(k, f"{d:.3f}") for k, d in ranked[:top]],
        title="likely key lengths (lower is better)",
    )


def _preview(data: bytes, width: int = 48) -> str:
    t = data.decode("latin-1").replace("\n", " ")
    if printable_ratio(data) <= 0.9:
        t = data.hex()
    return t if len(t) <= width else t[: width - 1] + "…"

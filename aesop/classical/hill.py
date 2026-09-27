"""
aesop.classical.hill — the Hill cipher (block matrix multiply mod 26).

Lester Hill's 1929 cipher was the first purely *polygraphic* scheme built on
linear algebra: letters are grouped into blocks of ``n`` and each block, seen as
a vector over ``Z_26``, is multiplied by a secret ``n × n`` key matrix.  Because
whole blocks move together, single-letter frequency analysis — the tool that
shreds Caesar, Affine and simple substitution — sees only noise.

That strength is also its fatal flaw.  The transform is *linear*, so a handful
of matching plaintext/ciphertext blocks pin the key exactly: stack the known
plaintext blocks into a matrix ``P`` and the ciphertext blocks into ``C``, then
solve ``P·K = C`` for the key ``K = P⁻¹·C`` (mod 26).  No searching, no scoring —
just one modular matrix inverse.  The fox does not guess the lock; he reads the
blueprint the maker left behind.

Like every AESOP technique module this file keeps two halves apart:

1. A **programmatic API** (pure functions on ``str`` / matrices) that is
   importable and unit-testable — :func:`encrypt`, :func:`decrypt`,
   :func:`matrix_inverse_mod`, :func:`known_plaintext_attack`.
2. A **command handler** wired into the CLI via :func:`aesop.registry.command`,
   which only marshals arguments, loads input and presents results.

Matrices use :mod:`numpy`; the modular inverse of the determinant comes from
:func:`aesop.core.util.modinv`.
"""
from __future__ import annotations

import math
import re
from itertools import combinations
from typing import List, Optional, Sequence, Union

import numpy as np

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import clean_text
from ..core.util import modinv

A = ord("A")
M = 26

Matrix = Union[np.ndarray, Sequence[Sequence[int]]]


# --------------------------------------------------------------------------- #
# Integer-exact linear algebra (numpy's float determinant is unreliable here)
# --------------------------------------------------------------------------- #
def _as_int_grid(matrix: Matrix) -> List[List[int]]:
    """Coerce a matrix-like into a square list-of-lists of Python ints."""
    grid = [[int(x) for x in row] for row in np.asarray(matrix).tolist()]
    n = len(grid)
    if n == 0 or any(len(row) != n for row in grid):
        raise ValueError("key matrix must be square (n × n)")
    return grid


def _det_int(grid: List[List[int]]) -> int:
    """Exact integer determinant by cofactor (Laplace) expansion.

    Fine for the small matrices a Hill cipher uses (n = 2, 3, …); avoids the
    floating-point rounding that makes ``numpy.linalg.det`` unsafe for the exact
    modular arithmetic we need.
    """
    n = len(grid)
    if n == 1:
        return grid[0][0]
    if n == 2:
        return grid[0][0] * grid[1][1] - grid[0][1] * grid[1][0]
    det = 0
    for j in range(n):
        minor = [row[:j] + row[j + 1:] for row in grid[1:]]
        det += ((-1) ** j) * grid[0][j] * _det_int(minor)
    return det


def _adjugate_int(grid: List[List[int]]) -> List[List[int]]:
    """Exact integer adjugate (transpose of the cofactor matrix)."""
    n = len(grid)
    cof = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = [row[:j] + row[j + 1:] for k, row in enumerate(grid) if k != i]
            sub = minor[0][0] if len(minor) == 1 else _det_int(minor)
            cof[i][j] = ((-1) ** (i + j)) * sub
    # adjugate = transpose of the cofactor matrix
    return [[cof[j][i] for j in range(n)] for i in range(n)]


def determinant_mod(matrix: Matrix, mod: int = M) -> int:
    """Determinant of ``matrix`` reduced mod ``mod`` (an exact integer)."""
    return _det_int(_as_int_grid(matrix)) % mod


def matrix_inverse_mod(matrix: Matrix, mod: int = M) -> np.ndarray:
    """Inverse of a square integer ``matrix`` modulo ``mod``.

    Computed the classical way — ``M⁻¹ ≡ det(M)⁻¹ · adj(M) (mod m)`` — using the
    exact integer determinant and adjugate above.  The determinant's modular
    inverse comes from :func:`aesop.core.util.modinv`.

    Raises :class:`ValueError` with a clear message if the determinant is not
    invertible mod ``mod`` (i.e. shares a factor with it), which is precisely
    when the matrix cannot serve as a Hill key.
    """
    grid = _as_int_grid(matrix)
    det = _det_int(grid) % mod
    g = math.gcd(det, mod)
    if g != 1:
        raise ValueError(
            f"matrix is not invertible mod {mod}: determinant {det} shares a "
            f"factor with {mod} (gcd = {g}). Choose a key whose determinant is "
            f"coprime with {mod} (for mod 26: odd and not a multiple of 13)."
        )
    det_inv = modinv(det, mod)
    adj = _adjugate_int(grid)
    n = len(grid)
    inv = np.empty((n, n), dtype=int)
    for i in range(n):
        for j in range(n):
            inv[i, j] = (det_inv * adj[i][j]) % mod
    return inv


# --------------------------------------------------------------------------- #
# Text <-> numeric-block helpers
# --------------------------------------------------------------------------- #
def _text_to_nums(text: str) -> List[int]:
    """Clean to A–Z and map each letter to 0–25."""
    return [ord(c) - A for c in clean_text(text)]


def _nums_to_text(nums: Sequence[int]) -> str:
    return "".join(chr(int(x) % M + A) for x in nums)


def _validate_square(K: np.ndarray) -> int:
    if K.ndim != 2 or K.shape[0] != K.shape[1]:
        raise ValueError("key matrix must be square (n × n)")
    return int(K.shape[0])


# --------------------------------------------------------------------------- #
# Programmatic API
# --------------------------------------------------------------------------- #
def encrypt(text: str, matrix: Matrix, pad: str = "X") -> str:
    """Hill-encrypt ``text`` with key ``matrix``.

    Letters are cleaned to A–Z, grouped into blocks of ``n`` (the matrix size),
    and each block row-vector ``p`` becomes ``c = p · K (mod 26)``.  A short
    final block is padded with ``pad`` (default ``X``).  Non-letters are dropped
    and the result is upper-case, as is conventional for Hill.
    """
    K = np.asarray(matrix, dtype=int) % M
    n = _validate_square(K)
    nums = _text_to_nums(text)
    pad_val = (ord(pad.upper()) - A) % M
    while len(nums) % n != 0:
        nums.append(pad_val)
    out: List[int] = []
    for i in range(0, len(nums), n):
        p = np.array(nums[i:i + n], dtype=int)
        out.extend(int(x) for x in (p @ K) % M)
    return _nums_to_text(out)


def decrypt(text: str, matrix: Matrix) -> str:
    """Hill-decrypt ``text`` with key ``matrix``.

    Inverts :func:`encrypt`: each ciphertext block ``c`` becomes
    ``p = c · K⁻¹ (mod 26)``, where ``K⁻¹`` is the modular inverse of the key.
    Raises :class:`ValueError` if the key is not invertible mod 26, or if the
    (cleaned) ciphertext length is not a multiple of the block size.
    """
    K = np.asarray(matrix, dtype=int) % M
    n = _validate_square(K)
    K_inv = matrix_inverse_mod(K, M)
    nums = _text_to_nums(text)
    if len(nums) % n != 0:
        raise ValueError(
            f"ciphertext has {len(nums)} letters, not a multiple of block size "
            f"{n}; the text may be truncated or the block size wrong"
        )
    out: List[int] = []
    for i in range(0, len(nums), n):
        c = np.array(nums[i:i + n], dtype=int)
        out.extend(int(x) for x in (c @ K_inv) % M)
    return _nums_to_text(out)


def known_plaintext_attack(plaintext: str, ciphertext: str, n: int) -> np.ndarray:
    """Recover an ``n × n`` Hill key from matched plaintext/ciphertext.

    Uses the linearity of the cipher: with ``n`` independent plaintext blocks
    stacked as the rows of ``P`` and the matching ciphertext blocks as the rows
    of ``C``, the key satisfies ``P · K = C (mod 26)``, so ``K = P⁻¹ · C``.

    The plaintext block matrix must be invertible mod 26; if the first ``n``
    blocks are dependent, every combination of the available blocks is tried
    until an invertible ``P`` is found.  Supports ``n = 2`` and ``n = 3`` (and
    any larger ``n`` given enough text).  Raises :class:`ValueError` if there is
    too little known text or no invertible block matrix exists.
    """
    if n < 2:
        raise ValueError("block size n must be at least 2")
    p_nums = _text_to_nums(plaintext)
    c_nums = _text_to_nums(ciphertext)
    if len(p_nums) != len(c_nums):
        raise ValueError(
            f"plaintext ({len(p_nums)} letters) and ciphertext "
            f"({len(c_nums)} letters) must be the same length"
        )
    blocks = len(p_nums) // n
    if blocks < n:
        raise ValueError(
            f"need at least {n} blocks ({n * n} letters) of matched text to "
            f"recover an {n}×{n} key; got {blocks} block(s)"
        )
    p_blocks = [p_nums[i * n:(i + 1) * n] for i in range(blocks)]
    c_blocks = [c_nums[i * n:(i + 1) * n] for i in range(blocks)]
    for combo in combinations(range(blocks), n):
        P = np.array([p_blocks[i] for i in combo], dtype=int) % M
        try:
            P_inv = matrix_inverse_mod(P, M)
        except ValueError:
            continue  # these blocks are linearly dependent mod 26; try others
        C = np.array([c_blocks[i] for i in combo], dtype=int) % M
        return (P_inv @ C) % M
    raise ValueError(
        "no set of n plaintext blocks is invertible mod 26; supply more "
        "matched plaintext/ciphertext so an independent block matrix exists"
    )


def parse_matrix(spec: str, size: Optional[int] = None) -> np.ndarray:
    """Parse a flat CSV key like ``'3,3,2,5'`` into an ``n × n`` numpy matrix.

    ``size`` fixes the block size; if omitted it is inferred as ``√len``, which
    must be a whole number.  Values are reduced mod 26.
    """
    parts = [p for p in re.split(r"[,\s]+", spec.strip()) if p]
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        raise ValueError(
            f"key must be whole numbers separated by commas or spaces; got {spec!r}"
        )
    total = len(nums)
    if total == 0:
        raise ValueError("empty key matrix")
    if size is None:
        n = math.isqrt(total)
        if n * n != total:
            raise ValueError(
                f"key has {total} entries, which is not a perfect square; pass "
                f"--size to set the block size"
            )
    else:
        n = size
        if total != n * n:
            raise ValueError(
                f"key has {total} entries but --size {n} needs exactly {n * n}"
            )
    if n < 2:
        raise ValueError("block size must be at least 2")
    return np.array(nums, dtype=int).reshape(n, n) % M


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "hill",
    group="classical",
    summary="Apply, invert, or key-recover a Hill cipher (block matrix mod 26)",
    manual="hill",
    args=io_args(positional="text", positional_help="the text to encode/decode (ciphertext for --decode)") + [
        arg("-k --key", "key matrix as flat CSV, e.g. '3,3,2,5' for [[3,3],[2,5]]"),
        arg("-s --size", "block size n (matrix is n×n); inferred from the key length if omitted", type=int),
        arg("--encode", "encrypt the input with --key", action="store_true"),
        arg("--decode", "decrypt the input with --key (the default when a key is given)", action="store_true"),
        arg("--known", "known plaintext for a known-plaintext key-recovery attack", metavar="PLAIN"),
        arg("--cipher", "ciphertext matching --known (its enciphered form)", metavar="CIPHER"),
    ],
    examples=[
        "aesop hill --encode --key '3,3,2,5' 'HELP'          # -> DPLE",
        "aesop hill --decode --key '3,3,2,5' 'DPLE'          # -> HELP",
        "aesop hill --known 'HELP' --cipher 'DPLE' --size 2  # recover the key",
        "echo 'DPLE' | aesop hill --key '3,3,2,5'",
    ],
    description="""
        The Hill cipher enciphers blocks of n letters at once by multiplying each
        block (a vector over Z_26) by a secret n×n key matrix, mod 26. Because it
        acts on whole blocks it defeats single-letter frequency analysis — but it
        is perfectly linear, so a few matched plaintext/ciphertext blocks recover
        the key outright.

        Give --key (flat CSV, row-major) with --encode or --decode to transform
        text directly; the block size is inferred from the key length or set with
        --size. To break a key, pass --known PLAIN and --cipher CIPHER (same
        length): AESOP stacks the blocks and solves P·K = C mod 26 by inverting
        the plaintext block matrix, printing the recovered matrix. Supports n=2
        and n=3 (larger with enough text). The key matrix must be invertible mod
        26 (its determinant coprime with 26); AESOP says so clearly if it isn't.
    """,
)
def cmd_hill(args, out) -> int:
    # --- Known-plaintext attack ------------------------------------------- #
    if args.known is not None or args.cipher is not None:
        if args.known is None or args.cipher is None:
            out.error("a known-plaintext attack needs both --known PLAIN and --cipher CIPHER")
            return 1
        n = args.size if args.size is not None else 2
        if n < 2:
            out.error(f"block size must be at least 2 (got {n})")
            return 1
        try:
            K = known_plaintext_attack(args.known, args.cipher, n)
        except ValueError as exc:
            out.error(str(exc))
            return 1
        flat = ",".join(str(int(x)) for x in K.flatten())
        out.success(f"recovered {n}×{n} key matrix")
        out.raw(flat)  # PRIMARY result: pipe-friendly flat CSV of the key
        out.print()
        out.table(
            [f"·{j}" for j in range(n)],
            [[int(x) for x in row] for row in K],
            title="key matrix (row-major)",
        )
        out.hint(f"decode with:  aesop hill --decode --key '{flat}' <ciphertext>")
        return 0

    # --- Direct transform (encode / decode) ------------------------------- #
    if not args.key:
        out.error(
            "give a key with --key (flat CSV, e.g. '3,3,2,5'), or run a "
            "known-plaintext attack with --known/--cipher"
        )
        return 1
    try:
        K = parse_matrix(args.key, args.size)
    except ValueError as exc:
        out.error(str(exc))
        return 1

    encode = bool(args.encode) and not bool(args.decode)
    # Encoding takes plaintext: load raw so prose isn't sniffed as hex/base64.
    inp = io.load(args, encoding="raw" if encode else None)
    try:
        result = encrypt(inp.text, K) if encode else decrypt(inp.text, K)
    except ValueError as exc:
        out.error(str(exc))
        if "invertible" in str(exc):
            out.hint("pick a key whose determinant is coprime with 26 (odd, not a multiple of 13)")
        return 1
    out.raw(result)  # PRIMARY result: the plaintext or ciphertext
    return 0

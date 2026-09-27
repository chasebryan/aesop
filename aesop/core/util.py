"""
aesop.core.util — number-theory and low-level helpers.

The quiet workhorses of the fable: gcd, modular inverses, the Chinese
Remainder Theorem, integer roots, continued fractions and primality.  Every
attack in :mod:`aesop.modern.rsa` leans on the routines defined here.

Everything is pure-Python and dependency-free at import time.  ``sympy`` is
used opportunistically for heavy factoring / primality when it is available,
but the module degrades gracefully without it.
"""
from __future__ import annotations

import math
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

try:  # optional, only used to accelerate a few heavy routines
    import sympy as _sympy  # type: ignore
    _HAVE_SYMPY = True
except Exception:  # pragma: no cover - environment dependent
    _sympy = None
    _HAVE_SYMPY = False


# --------------------------------------------------------------------------- #
# Basic modular arithmetic
# --------------------------------------------------------------------------- #
def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclid: return ``(g, x, y)`` with ``a*x + b*y == g == gcd(a, b)``."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """Modular inverse of ``a`` mod ``m``; raises ``ValueError`` if none exists."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse modulo {m} (gcd={g})")
    return x % m


def crt(remainders: Sequence[int], moduli: Sequence[int]) -> Tuple[int, int]:
    """Chinese Remainder Theorem.

    Solve ``x ≡ remainders[i] (mod moduli[i])`` for pairwise-coprime moduli.
    Returns ``(x, M)`` where ``M`` is the product of the moduli and ``x`` is the
    unique solution in ``[0, M)``.
    """
    if len(remainders) != len(moduli):
        raise ValueError("remainders and moduli must have equal length")
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        x += r * Mi * modinv(Mi, m)
    return x % M, M


def gcd(a: int, b: int) -> int:
    return math.gcd(a, b)


def lcm(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return abs(a // math.gcd(a, b) * b)


# --------------------------------------------------------------------------- #
# Integer roots
# --------------------------------------------------------------------------- #
def isqrt(n: int) -> int:
    """Integer square root (floor)."""
    if n < 0:
        raise ValueError("isqrt of negative number")
    return math.isqrt(n)


def is_perfect_square(n: int) -> bool:
    if n < 0:
        return False
    r = math.isqrt(n)
    return r * r == n


def iroot(n: int, k: int) -> Tuple[int, bool]:
    """Integer ``k``-th root of ``n``.

    Returns ``(r, exact)`` where ``r = floor(n ** (1/k))`` and ``exact`` says
    whether ``r ** k == n``.  Used by the low-exponent RSA attack (``e``-th root
    of an un-padded ciphertext).
    """
    if n < 0:
        raise ValueError("iroot of negative number")
    if k < 1:
        raise ValueError("k must be >= 1")
    if n in (0, 1) or k == 1:
        return n, True
    # Binary search for floor(n ** (1/k)).  lo must start at a valid lower bound
    # (1), NOT hi>>1 — the latter can exceed the true root for small n/large k.
    hi = 1 << ((n.bit_length() + k - 1) // k + 1)
    lo = 1
    while lo < hi:
        mid = (lo + hi + 1) >> 1
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** k == n


# --------------------------------------------------------------------------- #
# Continued fractions  (Wiener's attack, Diophantine approximation)
# --------------------------------------------------------------------------- #
def continued_fraction(num: int, den: int) -> List[int]:
    """Continued-fraction expansion ``[a0; a1, a2, ...]`` of ``num/den``."""
    cf: List[int] = []
    while den:
        cf.append(num // den)
        num, den = den, num - (num // den) * den
    return cf


def convergents(cf: Sequence[int]) -> Iterator[Tuple[int, int]]:
    """Yield successive convergents ``(numerator, denominator)`` of a CF."""
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for a in cf:
        n0, n1 = n1, a * n1 + n0
        d0, d1 = d1, a * d1 + d0
        yield n1, d1


# --------------------------------------------------------------------------- #
# Primality & factoring helpers
# --------------------------------------------------------------------------- #
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Deterministic Miller-Rabin for 64-bit, strong probable-prime beyond.

    Uses ``sympy.isprime`` when available (fully deterministic for our sizes),
    otherwise a Miller-Rabin with fixed + derived witnesses.
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    if _HAVE_SYMPY:
        return bool(_sympy.isprime(n))

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    # Deterministic witnesses for n < 3.3e24; extra pseudo-random-ish ones after.
    witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for i in range(rounds):
        witnesses.append(2 + (i * 2654435761) % (n - 3))
    for a in witnesses:
        a %= n
        if a < 2:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def prime_factors(n: int, limit: Optional[int] = None) -> List[int]:
    """Return the sorted list of prime factors with multiplicity.

    Prefers ``sympy.factorint`` when available; otherwise trial division up to
    ``limit`` (default: a bounded trial for small factors) followed by Pollard
    rho on the cofactor.
    """
    if n < 0:
        return [-1] + prime_factors(-n, limit)
    if n in (0, 1):
        return [n]
    if _HAVE_SYMPY and limit is None:
        out: List[int] = []
        for p, e in _sympy.factorint(n).items():
            out.extend([int(p)] * int(e))
        return sorted(out)

    factors: List[int] = []

    def _rho(m: int) -> int:
        if m % 2 == 0:
            return 2
        x = 2
        y = 2
        c = 1
        d = 1
        while d == 1:
            x = (x * x + c) % m
            y = (y * y + c) % m
            y = (y * y + c) % m
            d = math.gcd(abs(x - y), m)
            if d == m:
                c += 1
                x = y = 2
                d = 1
        return d

    def _factor(m: int) -> None:
        if m == 1:
            return
        if is_probable_prime(m):
            factors.append(m)
            return
        d = _rho(m)
        _factor(d)
        _factor(m // d)

    lim = limit if limit is not None else 1_000_000
    for p in _iter_small_primes(lim):
        while n % p == 0:
            factors.append(p)
            n //= p
        if p * p > n:
            break
    if n > 1:
        _factor(n)
    return sorted(factors)


def _iter_small_primes(limit: int) -> Iterable[int]:
    """Simple sieve generator up to ``limit`` (inclusive-ish)."""
    if limit < 2:
        return
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(limit) + 1):
        if sieve[i]:
            sieve[i * i :: i] = b"\x00" * len(sieve[i * i :: i])
    for i in range(2, limit + 1):
        if sieve[i]:
            yield i


# --------------------------------------------------------------------------- #
# Byte / int conversions
# --------------------------------------------------------------------------- #
def int_to_bytes(n: int, length: Optional[int] = None) -> bytes:
    """Big-endian conversion; auto-sizes when ``length`` is ``None``."""
    if n == 0:
        return b"\x00" if length is None else b"\x00" * length
    if length is None:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def humanize_int(n: int, max_digits: int = 40) -> str:
    """Compactly describe a big integer for CLI output."""
    s = str(n)
    bits = n.bit_length()
    if len(s) <= max_digits:
        return f"{s} ({bits} bits)"
    head = s[: max_digits // 2]
    tail = s[-(max_digits // 2) :]
    return f"{head}…{tail} ({len(s)} digits, {bits} bits)"

"""
aesop.modern.rsa — a textbook-RSA attack suite for CTF and teaching.

RSA is secure only when it is used correctly.  The fables in this file are all
the ways it is *mis*-used: primes chosen too close together, a private exponent
made too small to be convenient, a padding-free message cubed under ``e = 3``,
one modulus reused for two messages, or a fleet of keys sharing a prime because
somebody's entropy pool was empty at boot.  Each mistake has a matching fox.

Like every AESOP technique module this file keeps two halves apart:

1. A **programmatic API** — pure functions on plain ``int``/``bytes`` that never
   print.  Each attack returns a small result ``dict`` (with the recovered
   ``p``/``q``/``d``/``m`` and the ``method`` that found it) or ``None`` when it
   does not apply.  These are the importable, unit-testable core.
2. A thin **command handler** wired into the CLI via
   :func:`aesop.registry.command`, which only marshals arguments, loads any
   integers, runs the requested attack (or an ``auto`` chain) and presents the
   result via ``out``.

All the heavy number theory is delegated to :mod:`aesop.core.util` (``egcd``,
``modinv``, ``crt``, ``iroot``, ``isqrt``, ``continued_fraction``,
``convergents``, ``is_probable_prime``, ``int_to_bytes`` …).  ``sympy`` is used
opportunistically for small-factor work and is imported defensively so the
module never fails to load when it is absent.

None of this is a real cryptanalysis of properly padded, properly generated RSA.
It breaks *textbook* RSA and the classic implementation blunders — which is
exactly the corpus that shows up in challenges and coursework.
"""
from __future__ import annotations

import argparse
import math
from typing import Dict, List, Optional, Sequence

from ..registry import command, arg
from ..core.util import (
    egcd,
    modinv,
    crt,
    iroot,
    isqrt,
    is_perfect_square,
    continued_fraction,
    convergents,
    is_probable_prime,
    int_to_bytes,
)
from ..core.score import printable_ratio

try:  # optional accelerator for small / smooth factoring only
    import sympy as _sympy  # type: ignore
    _HAVE_SYMPY = True
except Exception:  # pragma: no cover - environment dependent
    _sympy = None
    _HAVE_SYMPY = False


# Sane default bounds so an interactive run never wedges the terminal.
DEFAULT_FERMAT_ITERS = 5_000_000
DEFAULT_RHO_ITERS = 8_000_000
DEFAULT_PM1_BOUND = 200_000
DEFAULT_TRIAL_BOUND = 1_000_000
DEFAULT_LOWE_TRIES = 200          # how many k in (c + k·n) to test for lowe
_SYMPY_SMALL_BITS = 110           # only unleash sympy.factorint below this size


# --------------------------------------------------------------------------- #
# Programmatic API — key reconstruction & decryption
# --------------------------------------------------------------------------- #
def private_exponent(p: int, q: int, e: int) -> int:
    """Recover the private exponent ``d`` from the primes and public exponent.

    ``d = e⁻¹ mod λ(n)`` where ``λ(n) = lcm(p−1, q−1)``; the Carmichael totient
    yields the canonical (smallest) ``d`` and always agrees with ``e⁻¹ mod φ(n)``
    for decryption.  Raises ``ValueError`` if ``e`` shares a factor with the
    totient (i.e. ``e`` is not a valid public exponent for this key).
    """
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    return modinv(e, lam)


def decrypt(c: int, d: int, n: int) -> int:
    """Plain RSA decryption / signing primitive: ``m = c^d mod n``."""
    return pow(c, d, n)


def message_bytes(m: int) -> bytes:
    """Big-endian byte encoding of a recovered message integer."""
    return int_to_bytes(m)


def reconstruct(
    n: Optional[int] = None,
    e: Optional[int] = None,
    p: Optional[int] = None,
    q: Optional[int] = None,
    d: Optional[int] = None,
    phi: Optional[int] = None,
    c: Optional[int] = None,
) -> Dict:
    """Fill in every derivable field of an RSA key from whatever is known.

    Give any workable subset — ``(p, q, e)``, ``(n, phi, e)``, ``(n, e, d)`` or
    a ready ``(n, d)`` — and this returns a dict with ``n, e, p, q, phi, d`` (as
    many as could be derived) plus, when ``c`` is supplied and ``d``/``n`` are
    known, the decrypted ``m``.  Purely arithmetic: it does no searching.
    """
    res: Dict = {"n": n, "e": e, "p": p, "q": q, "phi": phi, "d": d}

    if p and q:
        res["n"] = n = p * q
        res["phi"] = phi = (p - 1) * (q - 1)
        if e:
            res["d"] = d = private_exponent(p, q, e)

    elif n and phi:
        fac = factor_from_phi(n, phi)
        if fac:
            res["p"], res["q"] = p, q = fac["p"], fac["q"]
        if e:
            res["d"] = d = modinv(e, phi)

    elif n and e and d:
        fac = factor_from_d(n, e, d)
        if fac:
            res["p"], res["q"] = p, q = fac["p"], fac["q"]
            res["phi"] = (p - 1) * (q - 1)

    if c is not None and res.get("d") and res.get("n"):
        res["m"] = decrypt(c, res["d"], res["n"])
    return res


def factor_from_phi(n: int, phi: int) -> Optional[Dict]:
    """Recover ``p, q`` from ``n`` and ``φ(n)`` by solving the quadratic.

    ``p + q = n − φ(n) + 1`` and ``p·q = n``, so ``p, q`` are the roots of
    ``x² − (n − φ + 1)x + n``.  Returns ``{"p", "q"}`` or ``None`` if ``phi`` is
    inconsistent with ``n``.
    """
    s = n - phi + 1                       # p + q
    disc = s * s - 4 * n                  # (p − q)²
    if disc < 0 or not is_perfect_square(disc):
        return None
    t = isqrt(disc)
    p, q = (s + t) // 2, (s - t) // 2
    if p * q == n and 1 < p < n:
        return {"p": min(p, q), "q": max(p, q), "method": "from-phi"}
    return None


def factor_from_d(n: int, e: int, d: int) -> Optional[Dict]:
    """Factor ``n`` given a private exponent ``d`` (the classic ``ed−1`` method).

    ``ed − 1 = k·φ(n)`` is a multiple of the order; write it as ``2^s · t`` and
    look for a non-trivial square root of unity, which reveals a factor.  Runs a
    handful of random bases; returns ``{"p", "q"}`` or ``None``.
    """
    k = e * d - 1
    if k <= 0:
        return None
    s = 0
    t = k
    while t % 2 == 0:
        t //= 2
        s += 1
    for g in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(g, t, n)
        if x in (1, n - 1):
            continue
        for _ in range(s):
            y = pow(x, 2, n)
            if y == 1:
                p = math.gcd(x - 1, n)
                if 1 < p < n:
                    q = n // p
                    return {"p": min(p, q), "q": max(p, q), "method": "from-d"}
                break
            x = y
    return None


def _pack(n: int, p: int, method: str, **extra) -> Dict:
    """Normalise a discovered factor ``p`` of ``n`` into a result dict."""
    q = n // p
    lo, hi = (p, q) if p <= q else (q, p)
    out = {"p": lo, "q": hi, "method": method}
    out.update(extra)
    return out


# --------------------------------------------------------------------------- #
# Programmatic API — factoring attacks
# --------------------------------------------------------------------------- #
def factor_small(n: int, trial_bound: int = DEFAULT_TRIAL_BOUND) -> Optional[Dict]:
    """Catch small or smooth ``n`` with trial division, then ``sympy`` if tiny.

    Trial-divides by every prime up to ``trial_bound`` (fast: a sieve, then a
    ``p·p > cofactor`` cut-off).  If that peels off a factor the semiprime is
    solved.  Otherwise, only for genuinely small ``n`` (< ~110 bits) does it call
    ``sympy.factorint`` — never on a big semiprime, which would hang.  Returns
    ``{"p", "q", "method", "factors"}`` or ``None``.
    """
    if n < 4:
        return None
    if n % 2 == 0:
        return _pack(n, 2, "trial-division", factors=[2, n // 2])

    factors: List[int] = []
    m = n
    for p in _small_primes(trial_bound):
        if p * p > m:
            break
        while m % p == 0:
            factors.append(p)
            m //= p
    if factors:
        # A small factor was peeled off — treat n as p·(cofactor).
        p = factors[0]
        return _pack(n, p, "trial-division", factors=sorted(factors + ([m] if m > 1 else [])))

    if _HAVE_SYMPY and n.bit_length() <= _SYMPY_SMALL_BITS:
        fac = _sympy.factorint(n)
        primes: List[int] = []
        for base, exp in fac.items():
            primes.extend([int(base)] * int(exp))
        if len(primes) >= 2 and 1 < primes[0] < n:
            return _pack(n, primes[0], "sympy-factorint", factors=sorted(primes))
    return None


def fermat(n: int, max_iters: int = DEFAULT_FERMAT_ITERS) -> Optional[Dict]:
    """Fermat factorisation — devastating when ``p`` and ``q`` are close.

    Writes ``n = a² − b² = (a−b)(a+b)`` by walking ``a`` up from ``⌈√n⌉`` and
    testing whether ``a² − n`` is a perfect square.  The number of steps grows
    with ``|p − q|``, so it is bounded by ``max_iters`` and returns ``None`` if
    the primes turn out to be far apart.
    """
    if n <= 0 or n % 2 == 0:
        return None
    a = isqrt(n)
    if a * a < n:
        a += 1
    for i in range(max_iters):
        b2 = a * a - n
        if b2 >= 0 and is_perfect_square(b2):
            b = isqrt(b2)
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return _pack(n, p, "fermat", iterations=i + 1)
        a += 1
    return None


def pollard_pm1(n: int, B: int = DEFAULT_PM1_BOUND) -> Optional[Dict]:
    """Pollard's *p−1* — wins when some prime ``p`` has a ``B``-smooth ``p−1``.

    Computes ``a^(B!) mod n`` incrementally (``a = a^k`` for ``k = 2..B``) and
    watches ``gcd(a − 1, n)`` for a non-trivial factor.  ``B`` trades runtime for
    reach; returns ``{"p", "q", ...}`` or ``None`` if no factor's ``p−1`` is
    ``B``-smooth.
    """
    if n < 4:
        return None
    if n % 2 == 0:
        return _pack(n, 2, "pollard-pm1")
    a = 2
    for k in range(2, B + 1):
        a = pow(a, k, n)
        if k % 64 == 0 or k == B:
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return _pack(n, g, "pollard-pm1", bound=B)
            if g == n:
                return None  # overshot; caller can retry with a smaller B
    g = math.gcd(a - 1, n)
    if 1 < g < n:
        return _pack(n, g, "pollard-pm1", bound=B)
    return None


def pollard_rho(n: int, max_iters: int = DEFAULT_RHO_ITERS) -> Optional[Dict]:
    """Brent's improvement on Pollard's rho — the general small-factor workhorse.

    A cycle-finding walk under ``f(x) = x² + c mod n`` whose expected cost scales
    with ``⁴√n``, so it clears factors up to ~60–70 bits comfortably.  Bounded by
    ``max_iters`` and retries a few polynomials (``c``) before giving up with
    ``None``.
    """
    if n < 4:
        return None
    if n % 2 == 0:
        return _pack(n, 2, "pollard-rho")
    steps = 0
    for c in range(1, 20):
        y, m = 2, 128
        g = r = q = 1
        x = ys = 2
        aborted = False
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
                steps += 1
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = (q * abs(x - y)) % n
                    steps += 1
                g = math.gcd(q, n)
                k += m
                if steps > max_iters:
                    aborted = True
                    break
            r *= 2
            if aborted:
                break
        if aborted:
            return None
        if g == n:
            while True:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
                steps += 1
                if g > 1 or steps > max_iters:
                    break
        if 1 < g < n:
            return _pack(n, g, "pollard-rho", iterations=steps)
    return None


def factordb(n: int, timeout: float = 10.0) -> Optional[Dict]:
    """Look ``n`` up in factordb.com's public database (needs ``requests`` + net).

    Many CTF moduli are already factored online.  Guarded end-to-end: a missing
    ``requests``, no network, or a "still composite" answer all degrade to
    ``None`` rather than raising.
    """
    try:
        import requests  # optional; may be absent
    except Exception:
        return None
    try:
        resp = requests.get(
            "http://factordb.com/api", params={"query": str(n)}, timeout=timeout
        )
        data = resp.json()
    except Exception:
        return None
    primes: List[int] = []
    for entry in data.get("factors", []):
        try:
            base, exp = int(entry[0]), int(entry[1])
        except (ValueError, TypeError, IndexError):
            return None
        primes.extend([base] * exp)
    prod = 1
    for pr in primes:
        prod *= pr
    if len(primes) >= 2 and prod == n and primes[0] != n:
        return _pack(n, primes[0], "factordb", factors=sorted(primes))
    return None


# --------------------------------------------------------------------------- #
# Programmatic API — protocol / usage attacks
# --------------------------------------------------------------------------- #
def wiener(n: int, e: int) -> Optional[Dict]:
    """Wiener's continued-fraction attack — recovers a too-small ``d``.

    When ``d < ⅓·n^¼`` the fraction ``e/n`` closely approximates ``k/d``, so
    ``k/d`` appears among the convergents of the continued fraction of ``e/n``.
    Each convergent yields a candidate ``φ`` and hence a candidate factorisation;
    the real one is confirmed by ``p·q == n``.  Returns
    ``{"d", "p", "q", "phi", ...}`` or ``None``.
    """
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1                    # candidate p + q
        disc = s * s - 4 * n
        if disc < 0 or not is_perfect_square(disc):
            continue
        t = isqrt(disc)
        if (s + t) % 2 != 0:
            continue
        p, q = (s + t) // 2, (s - t) // 2
        if p > 1 and q > 1 and p * q == n:
            return {
                "d": d,
                "p": min(p, q),
                "q": max(p, q),
                "phi": phi,
                "method": "wiener",
            }
    return None


def low_exponent(c: int, e: int, n: int, tries: int = DEFAULT_LOWE_TRIES) -> Optional[Dict]:
    """Low-exponent attack: take the integer ``e``-th root of the ciphertext.

    With no padding and a small ``e`` (classically 3), if ``m^e < n`` then
    ``c = m^e`` outright and ``m`` is just ``⌊c^(1/e)⌋``.  To also cover the case
    where the message wrapped a few times, we test ``c + k·n`` for ``k`` up to
    ``tries``.  Returns ``{"m", "wraps", ...}`` or ``None``.
    """
    for k in range(tries):
        r, exact = iroot(c + k * n, e)
        if exact:
            return {"m": r, "wraps": k, "method": "low-exponent"}
    return None


def hastad_broadcast(cs: Sequence[int], ns: Sequence[int], e: int) -> Optional[Dict]:
    """Håstad's broadcast attack: same ``m`` sent to ``e`` recipients under ``e``.

    Given ``c_i = m^e mod n_i`` for ``e`` coprime moduli, CRT reconstructs
    ``m^e mod ∏n_i``; because ``m^e < ∏n_i`` this equals ``m^e`` exactly, so an
    integer ``e``-th root reveals ``m``.  Needs at least ``e`` ciphertext/modulus
    pairs.  Returns ``{"m", ...}`` or ``None``.
    """
    if e < 2 or len(cs) < e or len(ns) < e:
        return None
    try:
        x, _M = crt(list(cs[:e]), list(ns[:e]))
    except ValueError:
        return None  # moduli were not pairwise coprime
    r, exact = iroot(x, e)
    if exact:
        return {"m": r, "method": "hastad-broadcast"}
    return None


def common_modulus(c1: int, e1: int, c2: int, e2: int, n: int) -> Optional[Dict]:
    """Common-modulus attack: one ``m`` encrypted under two coprime exponents.

    With ``gcd(e1, e2) = 1`` there are integers ``a, b`` (from the extended
    Euclidean algorithm) with ``a·e1 + b·e2 = 1``, so
    ``m = c1^a · c2^b mod n``.  A negative coefficient is handled by inverting the
    corresponding ciphertext.  Returns ``{"m", ...}`` or ``None`` if the
    exponents share a factor.
    """
    g, a, b = egcd(e1, e2)
    if g != 1:
        return None
    if a < 0:
        c1 = modinv(c1, n)
        a = -a
    if b < 0:
        c2 = modinv(c2, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return {"m": m, "method": "common-modulus"}


def common_factor(moduli: Sequence[int]) -> Optional[Dict]:
    """Batch-GCD: find primes shared between moduli in a pile of public keys.

    A single repeated prime across two RSA moduli means both are trivially
    factored by ``gcd(n_i, n_j)`` — the classic consequence of weak key
    generation.  Scans every pair; returns ``{"shared": [...], "keys": {i: {p,q}}}``
    describing which moduli were cracked, or ``None`` if all are coprime.
    """
    shared: List[Dict] = []
    keys: Dict[int, Dict] = {}
    n = len(moduli)
    for i in range(n):
        for j in range(i + 1, n):
            g = math.gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i] and 1 < g < moduli[j]:
                shared.append({"i": i, "j": j, "p": g})
                for idx in (i, j):
                    keys[idx] = _pack(moduli[idx], g, "common-factor")
    if not shared:
        return None
    return {"shared": shared, "keys": keys, "method": "common-factor"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _small_primes(limit: int):
    """Yield primes up to ``limit`` via a simple byte sieve (dependency-free)."""
    if limit < 2:
        return
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, isqrt(limit) + 1):
        if sieve[i]:
            sieve[i * i :: i] = b"\x00" * len(sieve[i * i :: i])
    for i in range(2, limit + 1):
        if sieve[i]:
            yield i


def _decode_message(m: int):
    """Return ``(raw_bytes, display_text, printable)`` for a recovered message."""
    raw = int_to_bytes(m)
    printable = printable_ratio(raw) > 0.85
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", "replace")
    # Keep the display line safe to write to any stdout encoding.
    text = text.encode("utf-8", "replace").decode("utf-8")
    return raw, text, printable


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _intish(s: str) -> int:
    """argparse type: accept decimal, ``0x``/``0o``/``0b`` and ``_`` separators."""
    t = s.strip().replace("_", "").replace(" ", "")
    try:
        low = t.lower()
        if low.startswith("0x"):
            return int(t, 16)
        if low.startswith("0o"):
            return int(t, 8)
        if low.startswith("0b"):
            return int(t, 2)
        return int(t)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {s!r}")


_ATTACKS = [
    "auto", "fermat", "wiener", "pollard-pm1", "pollard-rho", "lowe",
    "hastad", "common-modulus", "common-factor", "factordb",
]


@command(
    "rsa",
    group="modern",
    summary="Attack textbook RSA — factor n, recover d, or decrypt c",
    manual="rsa",
    args=[
        arg("-n --modulus", "modulus n (repeatable for multi-key attacks)",
            action="append", type=_intish, metavar="N", dest="n"),
        arg("-e --exponent", "public exponent e (repeatable)",
            action="append", type=_intish, metavar="E", dest="e"),
        arg("-c --ciphertext", "ciphertext integer c (repeatable)",
            action="append", type=_intish, metavar="C", dest="c"),
        arg("-p --prime-p", "known prime factor p", type=_intish, dest="p"),
        # NOTE: -q is reserved globally for --quiet, so factor q is -Q / --prime-q.
        arg("-Q --prime-q", "known prime factor q", type=_intish, dest="q"),
        arg("-d", "known private exponent d", type=_intish),
        arg("--phi", "known Euler totient phi(n)", type=_intish),
        arg("--attack", "which attack to run (default: auto)",
            choices=_ATTACKS, default="auto"),
        arg("-B --bound", "smoothness bound B for Pollard p-1",
            type=_intish, default=DEFAULT_PM1_BOUND, dest="B"),
        arg("--max-iters", "iteration cap for fermat / rho",
            type=_intish, default=0, dest="max_iters"),
        arg("-f --file", "read 'name = value' / bare-int lines of parameters",
            metavar="PATH"),
    ],
    examples=[
        "aesop rsa -n 0x... -e 65537 -c 0x...            # auto: factor & decrypt",
        "aesop rsa --attack fermat -n 143 -e 7 -c 42     # close primes",
        "aesop rsa --attack wiener -n <N> -e <E>         # tiny private d",
        "aesop rsa --attack hastad -e 3 -c C1 -n N1 -c C2 -n N2 -c C3 -n N3",
        "aesop rsa --attack common-factor -f moduli.txt  # batch-GCD a keyfile",
    ],
    description="""
        A suite of the classic textbook-RSA attacks used in CTFs and courses:
        Fermat (close primes), Pollard p-1 and Brent's rho (small/smooth
        factors), Wiener (small private d), the low-exponent e-th root, Håstad
        broadcast, common-modulus, and batch-GCD across many keys (plus an
        optional factordb lookup).  Give what you know via -n/-e/-c/-p/-q/-d/
        --phi (each accepts decimal or 0x/0o/0b), or point --file at a list, and
        pick --attack (default 'auto' tries the applicable ones in order and
        stops once it factors n or recovers m).  Recovered p, q and d are shown;
        a recovered message is printed with out.raw as both an integer and
        decoded bytes so it pipes cleanly.
    """,
)
def cmd_rsa(args, out) -> int:
    ns, es, cs, scalars = _collect_params(args)
    if args.file:
        try:
            _merge_file(args.file, ns, es, cs, scalars)
        except OSError as exc:
            out.error(f"cannot read {args.file}: {exc}")
            return 2

    n = ns[0] if ns else None
    e = es[0] if es else None
    c = cs[0] if cs else None
    p, q, d, phi = scalars["p"], scalars["q"], scalars["d"], scalars["phi"]

    max_iters = args.max_iters or None
    attack = args.attack

    try:
        if attack == "common-factor":
            return _do_common_factor(out, ns, es, cs)
        if attack == "hastad":
            return _do_hastad(out, cs, ns, e)
        if attack == "common-modulus":
            return _do_common_modulus(out, cs, es, n)
        if attack == "lowe":
            return _do_lowe(out, c, e, n)
        if attack in ("fermat", "wiener", "pollard-pm1", "pollard-rho", "factordb"):
            return _do_single_factor(out, attack, n, e, c, args.B, max_iters)
        # auto
        return _do_auto(out, ns, es, cs, p, q, d, phi, args.B, max_iters)
    except ValueError as exc:
        out.error(str(exc))
        return 2


# -- argument collection ---------------------------------------------------- #
def _collect_params(args):
    ns = list(args.n) if args.n else []
    es = list(args.e) if args.e else []
    cs = list(args.c) if args.c else []
    scalars = {"p": args.p, "q": args.q, "d": args.d, "phi": args.phi}
    return ns, es, cs, scalars


def _merge_file(path: str, ns, es, cs, scalars) -> None:
    """Read ``name = value`` / ``name: value`` / bare-int lines into the params."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            key, sep, val = _split_kv(line)
            if not sep:
                # a bare integer line → another ciphertext
                try:
                    cs.append(_intish(line))
                except argparse.ArgumentTypeError:
                    pass
                continue
            try:
                num = _intish(val)
            except argparse.ArgumentTypeError:
                continue
            key = key.lower()
            if key in ("n", "modulus"):
                ns.append(num)
            elif key in ("e", "exponent"):
                es.append(num)
            elif key in ("c", "ct", "ciphertext"):
                cs.append(num)
            elif key in ("p", "q", "d"):
                scalars[key] = num
            elif key in ("phi", "totient"):
                scalars["phi"] = num


def _split_kv(line: str):
    for sep in ("=", ":"):
        if sep in line:
            k, _, v = line.partition(sep)
            return k.strip(), True, v.strip()
    return line, False, ""


# -- presentation ----------------------------------------------------------- #
def _show_key(out, res: Dict, n: Optional[int]) -> None:
    """Show recovered p/q/d/phi via keyval (secondary/diagnostic info)."""
    pairs = []
    if n is not None:
        pairs.append(("n", f"{n}  ({n.bit_length()} bits)"))
    for label in ("p", "q", "phi", "d"):
        if res.get(label) is not None:
            pairs.append((label, str(res[label])))
    if res.get("method"):
        pairs.append(("method", res["method"]))
    if pairs:
        out.keyval(pairs, title="recovered key material")


def _emit_message(out, m: int) -> None:
    """Emit a recovered message as the PRIMARY result: raw int + decoded bytes."""
    raw, text, printable = _decode_message(m)
    out.success("message recovered")
    out.raw(str(m))                       # integer form (pipeable)
    out.raw(text)                         # decoded bytes (pipeable)
    if not printable:
        out.keyval([("hex", raw.hex())], title="raw bytes (non-printable)")


def _emit_factor_key(out, res: Dict, n: int, e: Optional[int], c: Optional[int]) -> int:
    """After factoring n: derive d, decrypt c if present, present everything."""
    p, q = res["p"], res["q"]
    out.success(f"factored n via {res.get('method', 'factoring')}")
    key = reconstruct(n=n, e=e, p=p, q=q, c=c)
    _show_key(out, {**res, **key}, n)

    if c is not None and key.get("m") is not None:
        _emit_message(out, key["m"])
    elif key.get("d") is not None:
        # No ciphertext: the recovered key IS the primary result.
        out.raw(str(key["d"]))
    else:
        # No e supplied: emit the smaller prime as the primary result.
        out.raw(str(p))
        out.hint("supply -e to also recover the private exponent d")
    return 0


# -- per-attack handlers ---------------------------------------------------- #
def _need(value, what: str):
    if value is None:
        raise ValueError(f"this attack needs {what}")
    return value


def _do_single_factor(out, attack, n, e, c, B, max_iters) -> int:
    _need(n, "a modulus (-n)")
    if attack == "fermat":
        res = fermat(n, max_iters or DEFAULT_FERMAT_ITERS)
        if not res:
            out.error("fermat failed — the primes are probably far apart")
            out.hint("try --attack pollard-rho, or raise --max-iters")
            return 1
    elif attack == "wiener":
        _need(e, "a public exponent (-e)")
        res = wiener(n, e)
        if not res:
            out.error("wiener failed — d is not small enough (needs d < n^0.25/3)")
            return 1
        out.success("recovered a short private exponent d")
        key = reconstruct(n=n, e=e, p=res["p"], q=res["q"], c=c)
        _show_key(out, {**res, **key}, n)
        if c is not None and key.get("m") is not None:
            _emit_message(out, key["m"])
        else:
            out.raw(str(res["d"]))
        return 0
    elif attack == "pollard-pm1":
        res = pollard_pm1(n, B)
        if not res:
            out.error("pollard p-1 failed — no prime has a B-smooth p-1")
            out.hint(f"raise -B (was {B})")
            return 1
    elif attack == "pollard-rho":
        res = pollard_rho(n, max_iters or DEFAULT_RHO_ITERS)
        if not res:
            out.error("pollard rho hit its iteration bound without a factor")
            out.hint("the factors are likely too large for rho; raise --max-iters")
            return 1
    else:  # factordb
        res = factordb(n)
        if not res:
            out.error("factordb returned no usable factorisation")
            out.hint("requires the 'requests' package and network access")
            return 1
    return _emit_factor_key(out, res, n, e, c)


def _do_lowe(out, c, e, n) -> int:
    _need(c, "a ciphertext (-c)")
    if e is None:
        e = 3
        out.hint("no -e given; assuming e=3 for the low-exponent attack")
    _need(n, "a modulus (-n)")
    res = low_exponent(c, e, n)
    if not res:
        out.error("low-exponent attack failed — m^e is not a clean e-th root")
        out.hint("m^e likely exceeds n (message not small); this attack needs m^e < n")
        return 1
    if res.get("wraps"):
        out.info(f"message wrapped the modulus {res['wraps']} time(s)")
    _emit_message(out, res["m"])
    return 0


def _do_common_modulus(out, cs, es, n) -> int:
    _need(n, "a modulus (-n)")
    if len(cs) < 2 or len(es) < 2:
        raise ValueError("common-modulus needs two ciphertexts (-c) and two exponents (-e)")
    res = common_modulus(cs[0], es[0], cs[1], es[1], n)
    if not res:
        out.error("common-modulus failed — the two exponents are not coprime")
        return 1
    _emit_message(out, res["m"])
    return 0


def _do_hastad(out, cs, ns, e) -> int:
    _need(e, "a public exponent (-e)")
    if len(cs) < e or len(ns) < e:
        raise ValueError(
            f"hastad broadcast needs at least e={e} ciphertext/modulus pairs "
            f"(got {len(cs)} c / {len(ns)} n)"
        )
    res = hastad_broadcast(cs, ns, e)
    if not res:
        out.error("hastad broadcast failed — moduli not coprime, or m^e ≥ ∏n_i")
        return 1
    _emit_message(out, res["m"])
    return 0


def _do_common_factor(out, ns, es, cs) -> int:
    if len(ns) < 2:
        raise ValueError("common-factor needs at least two moduli (-n, repeatable, or --file)")
    res = common_factor(ns)
    if not res:
        out.error("no shared prime found — every pair of moduli is coprime")
        return 1
    out.success(f"found {len(res['shared'])} shared prime(s) across {len(ns)} moduli")
    out.table(
        ["modulus #", "modulus #", "shared prime p"],
        [(s["i"], s["j"], str(s["p"])) for s in res["shared"]],
        title="pairwise GCD hits",
    )
    # Primary result: the recovered factor(s), one per cracked modulus.
    for idx in sorted(res["keys"]):
        key = res["keys"][idx]
        e = es[idx] if idx < len(es) else (es[0] if es else None)
        full = reconstruct(n=ns[idx], e=e, p=key["p"], q=key["q"],
                           c=cs[idx] if idx < len(cs) else None)
        _show_key(out, {**key, **full}, ns[idx])
        if full.get("m") is not None:
            _emit_message(out, full["m"])
        elif full.get("d") is not None:
            out.raw(str(full["d"]))
        else:
            out.raw(str(key["p"]))
    return 0


# -- auto orchestrator ------------------------------------------------------ #
def _do_auto(out, ns, es, cs, p, q, d, phi, B, max_iters) -> int:
    """Try the applicable attacks in a sensible order; stop at the first win."""
    n = ns[0] if ns else None
    e = es[0] if es else None
    c = cs[0] if cs else None

    # 0. Already have enough to reconstruct/decrypt directly.
    if (p and q) or (n and phi) or (n and e and d) or (n and d):
        key = reconstruct(n=n, e=e, p=p, q=q, d=d, phi=phi, c=c)
        if key.get("n"):
            n = key["n"]
        out.success("reconstructed key from supplied parameters")
        _show_key(out, key, n)
        if c is not None and key.get("d") and key.get("n"):
            _emit_message(out, decrypt(c, key["d"], key["n"]))
        elif key.get("d") is not None:
            out.raw(str(key["d"]))
        elif key.get("p") is not None:
            out.raw(str(key["p"]))
        return 0

    # 1. Many moduli → batch GCD.
    if len(ns) >= 2:
        res = common_factor(ns)
        if res:
            out.info("auto: shared prime detected across moduli")
            return _do_common_factor(out, ns, es, cs)

    # 2. One modulus, two exponents, two ciphertexts → common modulus.
    if n and len(es) >= 2 and len(cs) >= 2 and es[0] != es[1]:
        res = common_modulus(cs[0], es[0], cs[1], es[1], n)
        if res:
            out.info("auto: common-modulus (same n, coprime e)")
            _emit_message(out, res["m"])
            return 0

    # 3. Small e with enough broadcast pairs → Håstad.
    if e and e <= 11 and len(cs) >= e and len(ns) >= e:
        res = hastad_broadcast(cs, ns, e)
        if res:
            out.info("auto: Håstad broadcast (CRT + e-th root)")
            _emit_message(out, res["m"])
            return 0

    # 4. Small e and a ciphertext → try the low-exponent e-th root.
    if c is not None and n and e and e <= 11:
        res = low_exponent(c, e, n)
        if res:
            out.info("auto: low-exponent e-th root")
            _emit_message(out, res["m"])
            return 0

    if not n:
        out.error("nothing to attack — supply at least a modulus (-n)")
        out.hint("see `aesop manual rsa` for what each attack needs")
        return 2

    # 5. Factoring ladder: cheap and specialised first, general last.
    out.info(f"auto: attempting to factor n ({n.bit_length()} bits)")

    res = factor_small(n)
    if res:
        return _emit_factor_key(out, res, n, e, c)

    if e:
        res = wiener(n, e)
        if res:
            out.success("auto: Wiener recovered a short private exponent")
            key = reconstruct(n=n, e=e, p=res["p"], q=res["q"], c=c)
            _show_key(out, {**res, **key}, n)
            if c is not None and key.get("m") is not None:
                _emit_message(out, key["m"])
            else:
                out.raw(str(res["d"]))
            return 0

    res = fermat(n, max_iters or DEFAULT_FERMAT_ITERS)
    if res:
        return _emit_factor_key(out, res, n, e, c)

    res = pollard_pm1(n, B)
    if res:
        return _emit_factor_key(out, res, n, e, c)

    res = pollard_rho(n, max_iters or DEFAULT_RHO_ITERS)
    if res:
        return _emit_factor_key(out, res, n, e, c)

    out.error("auto: could not factor n with the built-in attacks")
    out.hint("skipped: exhaustive factoring (n is too large for the bounded methods)")
    out.hint("try `--attack factordb`, raise -B / --max-iters, or supply -p/-q/-d/--phi")
    return 1

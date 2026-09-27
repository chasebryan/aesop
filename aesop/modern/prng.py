"""
aesop.modern.prng — predicting "random" numbers that were never random enough.

A pseudo-random generator is a fable told to a program: *trust me, these numbers
are unpredictable.*  The fox in this file is the one who sat and watched the
storyteller long enough to learn the trick.  Two classic generators give
themselves away completely once you have seen enough of their output:

* **MT19937** (the Mersenne Twister behind Python's :mod:`random`, PHP's
  ``mt_rand``, and countless games and tokens).  Its output is the internal
  state passed through an *invertible* scrambling step called *tempering*.  Undo
  the tempering on **624** consecutive 32-bit outputs and you have reconstructed
  the entire state — from there every future number is deterministic.
* **LCG** (the linear congruential generator, ``x → a·x + c mod m``, the engine
  of ``rand()`` in old C libraries, ``java.util.Random`` and many toys).  A
  handful of consecutive outputs pins down ``a``, ``c`` and even the modulus
  ``m`` by taking greatest common divisors of small determinants.

Like every AESOP technique module this file keeps two halves apart:

1. A **programmatic API** — pure functions and small predictor objects that take
   plain ``int`` sequences and never print.  These are the importable,
   unit-testable core (:func:`untemper`, :func:`mt19937_recover`,
   :func:`lcg_recover`).
2. A thin **command handler** wired into the CLI via
   :func:`aesop.registry.command`, which only marshals arguments, gathers the
   number stream, runs the recovery and presents the result via ``out``.

None of this breaks a cryptographically secure PRNG (``secrets``,
``/dev/urandom``, ``os.urandom``).  It breaks the *statistical* generators that
are forever being misused where a secure one was required — which is exactly the
corpus that shows up in CTFs, coursework and the occasional real-world token.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from dataclasses import dataclass
from typing import List, Optional, Sequence

from ..registry import command, arg
from ..core.util import modinv

# --------------------------------------------------------------------------- #
# MT19937 constants (the reference 32-bit Mersenne Twister)
# --------------------------------------------------------------------------- #
_W = 32
_MASK32 = 0xFFFFFFFF
_N = 624                 # degree of recurrence — outputs needed for a full clone
_M = 397                 # middle word offset
_MATRIX_A = 0x9908B0DF   # twist constant
_UPPER_MASK = 0x80000000 # most significant bit
_LOWER_MASK = 0x7FFFFFFF # the remaining 31 bits

# Tempering parameters — the (shift, mask) pairs applied to each state word.
_TEMPER_B = 0x9D2C5680   # << 7  mask
_TEMPER_C = 0xEFC60000   # << 15 mask
_TEMPER_U = 11           # >> 11 shift (mask is all-ones for the reference MT)
_TEMPER_S = 7
_TEMPER_T = 15
_TEMPER_L = 18           # >> 18 shift


# --------------------------------------------------------------------------- #
# Programmatic API — MT19937
# --------------------------------------------------------------------------- #
def _undo_xor_rshift(y: int, shift: int, mask: int = _MASK32) -> int:
    """Invert ``y = x ^ ((x >> shift) & mask)`` for a 32-bit ``x``.

    Right-shifting leaves the top ``shift`` bits of ``x`` untouched, so each pass
    of the fix-point iteration recovers another ``shift`` high bits; it converges
    after ``ceil(32/shift)`` rounds.
    """
    x = y
    for _ in range(_W // shift + 1):
        x = y ^ ((x >> shift) & mask)
    return x & _MASK32


def _undo_xor_lshift(y: int, shift: int, mask: int) -> int:
    """Invert ``y = x ^ ((x << shift) & mask)`` for a 32-bit ``x``.

    Symmetric to :func:`_undo_xor_rshift`: left-shifting preserves the low
    ``shift`` bits, so the iteration climbs from the bottom of the word up.
    """
    x = y
    for _ in range(_W // shift + 1):
        x = y ^ ((x << shift) & mask)
    return x & _MASK32


def temper(x: int) -> int:
    """Apply MT19937's tempering transform to one 32-bit state word.

    This is the forward step: the generator never exposes ``x`` directly, only
    ``temper(x)``.  Provided so :func:`untemper` can be round-trip tested.
    """
    y = x & _MASK32
    y ^= y >> _TEMPER_U
    y ^= (y << _TEMPER_S) & _TEMPER_B
    y ^= (y << _TEMPER_T) & _TEMPER_C
    y ^= y >> _TEMPER_L
    return y & _MASK32


def untemper(y: int) -> int:
    """Reverse MT19937's tempering transform for one 32-bit output.

    Tempering is a composition of four invertible xor-shift steps; undoing them
    in the opposite order recovers the raw state word ``x`` such that
    ``temper(x) == y``.  This is the single primitive the whole state-recovery
    attack is built on — one call per captured output.
    """
    y &= _MASK32
    y = _undo_xor_rshift(y, _TEMPER_L)                 # undo  y ^= y >> 18
    y = _undo_xor_lshift(y, _TEMPER_T, _TEMPER_C)      # undo  y ^= (y << 15) & c
    y = _undo_xor_lshift(y, _TEMPER_S, _TEMPER_B)      # undo  y ^= (y << 7)  & b
    y = _undo_xor_rshift(y, _TEMPER_U)                 # undo  y ^= y >> 11
    return y & _MASK32


class MT19937:
    """A minimal, self-contained 32-bit Mersenne Twister.

    Faithful to the reference algorithm and to CPython's ``random`` module for
    full 32-bit words, so a state spliced in from :func:`untemper`-ed outputs
    reproduces :meth:`random.Random.getrandbits` ``(32)`` exactly.  Kept
    dependency-free on purpose — no reliance on CPython's private state layout.
    """

    def __init__(self, state: Optional[Sequence[int]] = None, index: int = _N):
        if state is None:
            self.mt = [0] * _N
            self.index = _N + 1
        else:
            if len(state) != _N:
                raise ValueError(f"MT19937 state needs exactly {_N} words, got {len(state)}")
            self.mt = [w & _MASK32 for w in state]
            self.index = index

    @classmethod
    def from_seed(cls, seed: int) -> "MT19937":
        """Initialise from an integer seed (reference ``init_genrand``)."""
        mt = [0] * _N
        mt[0] = seed & _MASK32
        for i in range(1, _N):
            mt[i] = (1812433253 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & _MASK32
        return cls(mt, index=_N)

    @classmethod
    def from_outputs(cls, outputs: Sequence[int]) -> "MT19937":
        """Clone the generator from >=624 consecutive tempered 32-bit outputs.

        Any 624 consecutive outputs form a complete, valid state window (the MT
        recurrence is a sliding one), so the clone continues the stream from the
        output *after* the last one supplied — regardless of block alignment.
        """
        outs = [o & _MASK32 for o in outputs]
        if len(outs) < _N:
            raise ValueError(f"need at least {_N} consecutive 32-bit outputs, got {len(outs)}")
        window = outs[-_N:]
        state = [untemper(o) for o in window]
        return cls(state, index=_N)

    def _twist(self) -> None:
        for i in range(_N):
            y = (self.mt[i] & _UPPER_MASK) | (self.mt[(i + 1) % _N] & _LOWER_MASK)
            nxt = self.mt[(i + _M) % _N] ^ (y >> 1)
            if y & 1:
                nxt ^= _MATRIX_A
            self.mt[i] = nxt & _MASK32
        self.index = 0

    def next_uint32(self) -> int:
        """Return the next tempered 32-bit output (advances the state)."""
        if self.index >= _N:
            if self.index == _N + 1:
                # Never seeded; behave like the reference default seed 5489.
                seeded = MT19937.from_seed(5489)
                self.mt = seeded.mt
                self.index = _N
            self._twist()
        y = temper(self.mt[self.index])
        self.index += 1
        return y


@dataclass
class MT19937Predictor:
    """Predictor built from a recovered MT19937 state.

    Wraps a cloned :class:`MT19937`; :meth:`predict_next` reproduces the exact
    sequence of 32-bit outputs the target generator will produce next.
    """

    mt: MT19937

    def predict_next(self, n: int = 1) -> List[int]:
        """Return the next ``n`` 32-bit outputs the target will emit."""
        return [self.mt.next_uint32() for _ in range(n)]

    def state(self) -> List[int]:
        """The recovered raw internal state (624 words) — for e.g. setstate."""
        return list(self.mt.mt)


def mt19937_recover(outputs: Sequence[int]) -> MT19937Predictor:
    """Rebuild MT19937's internal state from consecutive outputs and predict.

    Give at least **624** consecutive 32-bit outputs (``getrandbits(32)``,
    ``mt_rand`` scaled to 32 bits, etc.).  Each is un-tempered back into a state
    word; the 624 words are spliced into a fresh :class:`MT19937`, which then
    reproduces every subsequent output.  Returns an :class:`MT19937Predictor`
    whose :meth:`~MT19937Predictor.predict_next` continues the stream from right
    after the last supplied output.
    """
    clone = MT19937.from_outputs(outputs)
    return MT19937Predictor(clone)


# --------------------------------------------------------------------------- #
# Programmatic API — Linear Congruential Generators
# --------------------------------------------------------------------------- #
@dataclass
class LCGParams:
    """Recovered parameters of an LCG ``x -> (a*x + c) mod m`` plus a predictor."""

    a: int
    c: int
    m: int
    last: int   # the last known output, so prediction continues the stream

    def step(self) -> int:
        self.last = (self.a * self.last + self.c) % self.m
        return self.last

    def predict_next(self, n: int = 1) -> List[int]:
        """Return the next ``n`` outputs the LCG will emit."""
        return [self.step() for _ in range(n)]

    def reproduces(self, sequence: Sequence[int]) -> bool:
        """True if these parameters regenerate every step of ``sequence``."""
        seq = [int(x) for x in sequence]
        for x0, x1 in zip(seq, seq[1:]):
            if (self.a * x0 + self.c) % self.m != x1 % self.m:
                return False
        return True


def lcg_recover_modulus(sequence: Sequence[int]) -> Optional[int]:
    """Recover an LCG modulus ``m`` from consecutive outputs (unknown ``a, c``).

    Differencing kills the additive constant: with ``t_i = s_{i+1} - s_i`` we get
    ``t_{i+1} ≡ a·t_i (mod m)``, so every 2x2 determinant
    ``u_i = t_{i+2}·t_i - t_{i+1}²`` is an exact multiple of ``m``.  The greatest
    common divisor of enough such ``u_i`` collapses to ``m`` itself.  Needs at
    least four outputs; more make the answer certain.  Returns ``m`` or ``None``.
    """
    seq = [int(x) for x in sequence]
    if len(seq) < 4:
        return None
    diffs = [b - a for a, b in zip(seq, seq[1:])]
    dets = [
        t2 * t0 - t1 * t1
        for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])
    ]
    m = 0
    for d in dets:
        m = math.gcd(m, abs(d))
    if m <= 1:
        return None
    # Each determinant is an exact multiple of the true modulus, so the gcd of
    # enough of them converges toward m.  It can still overshoot by a small
    # factor — notably a power of two when m itself is a power of two, since the
    # differences then share extra factors of 2.  Reduce it to the smallest
    # divisor that still fits the whole sequence, which resolves that case.
    return _reduce_modulus(seq, m)


def _params_for_modulus(seq: List[int], m: int) -> Optional[tuple]:
    """Return ``(a, c)`` fitting ``seq`` under modulus ``m``, or ``None``.

    Solves ``a`` from the first invertible successive difference, derives
    ``c = s_1 - a·s_0``, and returns the pair only if it reproduces *every*
    transition in ``seq``.
    """
    for i in range(len(seq) - 2):
        d = (seq[i + 1] - seq[i]) % m
        if d and math.gcd(d, m) == 1:
            a = ((seq[i + 2] - seq[i + 1]) * modinv(d, m)) % m
            c = (seq[i + 1] - a * seq[i]) % m
            if all((a * x0 + c) % m == x1 % m for x0, x1 in zip(seq, seq[1:])):
                return a, c
            return None
    return None


def _reduce_modulus(seq: List[int], m: int) -> int:
    """Shrink an over-estimated modulus to the smallest divisor that still fits.

    Repeatedly divides out a prime factor whenever the quotient (a) stays above
    every observed output and (b) still reproduces the whole sequence with a
    re-derived ``a, c``.  This peels the spurious factor off a gcd that overshot
    (e.g. ``2^32`` down to a true ``2^31``).  Factoring is bounded so the routine
    never wedges on an implausibly large gcd.
    """
    hi = max((abs(x) for x in seq), default=0)
    if m.bit_length() > 160:
        return m  # too large to factor safely — trust the raw gcd
    try:
        from ..core.util import prime_factors
    except Exception:  # pragma: no cover - core always present
        return m
    while True:
        try:
            primes = sorted(set(prime_factors(m)))
        except Exception:
            return m
        for p in primes:
            if p < 2:
                continue
            cand = m // p
            if cand <= hi:
                continue
            if _params_for_modulus(seq, cand) is not None:
                m = cand
                break
        else:
            return m


def lcg_recover_multiplier(sequence: Sequence[int], m: int) -> int:
    """Recover the multiplier ``a`` given the modulus ``m``.

    From ``s_{i+2} - s_{i+1} ≡ a·(s_{i+1} - s_i) (mod m)`` we solve
    ``a = (s_{i+2}-s_{i+1})·(s_{i+1}-s_i)⁻¹``, using the first consecutive pair
    whose difference is invertible modulo ``m``.
    """
    seq = [int(x) for x in sequence]
    for i in range(len(seq) - 2):
        d = (seq[i + 1] - seq[i]) % m
        if d and math.gcd(d, m) == 1:
            return ((seq[i + 2] - seq[i + 1]) * modinv(d, m)) % m
    raise ValueError(
        "could not recover the multiplier: no invertible successive difference "
        "(supply more outputs, or a known modulus)"
    )


def lcg_recover(sequence: Sequence[int], modulus: Optional[int] = None) -> LCGParams:
    """Recover ``(a, c, m)`` of an LCG from consecutive outputs, then predict.

    Give three or more consecutive full outputs ``s_0, s_1, …``.  When
    ``modulus`` is unknown it is derived first (see :func:`lcg_recover_modulus`),
    then the multiplier ``a`` and increment ``c = s_1 - a·s_0 (mod m)`` follow by
    elementary modular algebra.  Returns an :class:`LCGParams` whose
    :meth:`~LCGParams.predict_next` continues the stream from the last output.
    Raises ``ValueError`` when the data is insufficient.
    """
    seq = [int(x) for x in sequence]
    m = modulus
    if m is None:
        if len(seq) < 6:
            raise ValueError(
                "recovering an unknown modulus needs at least 6 consecutive "
                "outputs; supply more, or pass a known modulus"
            )
        m = lcg_recover_modulus(seq)
        if not m or m <= 1:
            raise ValueError(
                "could not recover the modulus from this data; supply it with "
                "--modulus, or provide more consecutive outputs"
            )
    elif len(seq) < 3:
        raise ValueError("need at least 3 consecutive LCG outputs")
    fitted = _params_for_modulus(seq, m)
    if fitted is not None:
        a, c = fitted
    else:
        # Best effort for reporting; the caller verifies via LCGParams.reproduces.
        a = lcg_recover_multiplier(seq, m)
        c = (seq[1] - a * seq[0]) % m
    return LCGParams(a=a, c=c, m=m, last=seq[-1] % m)


# --------------------------------------------------------------------------- #
# CLI — argument helpers
# --------------------------------------------------------------------------- #
def _intish(s: str) -> int:
    """argparse type: accept decimal, ``0x``/``0o``/``0b`` and ``_`` separators."""
    t = s.strip().replace("_", "").replace(",", "")
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


_TOKEN_RE = re.compile(r"[-+]?(?:0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+|\d+)")


def parse_number_stream(text: str) -> List[int]:
    """Parse a blob of numbers: a JSON array, or whitespace/comma-separated ints.

    Understands ``[1, 2, 3]`` JSON arrays as well as one-per-line or
    space/comma-separated decimal / ``0x`` / ``0o`` / ``0b`` integers.  Any
    surrounding prose or brackets are ignored so pasted challenge output "just
    works".
    """
    t = text.strip()
    if not t:
        return []
    if t[0] == "[":
        try:
            data = json.loads(t)
            return [int(x) for x in data]
        except (ValueError, TypeError):
            pass
    return [int(tok, 0) for tok in _TOKEN_RE.findall(t)]


def _gather_numbers(args, out) -> Optional[List[int]]:
    """Collect the integer stream from positional values, ``--file`` or stdin."""
    # Priority mirrors io.load: file > literal values > stdin.
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            out.error(f"cannot read {args.file}: {exc}")
            return None
        return parse_number_stream(text)

    if args.values:
        return list(args.values)

    import sys
    if not sys.stdin.isatty():
        return parse_number_stream(sys.stdin.read())

    out.error("no numbers given — pass values, --file PATH, or pipe them via stdin")
    out.hint("each output on its own line, or a JSON array like [123, 456, …]")
    return None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "prng",
    group="modern",
    summary="Predict non-cryptographic PRNGs — clone MT19937, solve an LCG",
    manual="prng",
    aliases=["mt19937"],
    args=[
        arg("values", "PRNG outputs (or use --file / pipe via stdin)",
            nargs="*", type=_intish, metavar="OUTPUT"),
        arg("--mt", "MT19937 mode: clone the state from 624+ outputs",
            action="store_true"),
        arg("--lcg", "LCG mode: recover a, c, m from consecutive outputs",
            action="store_true"),
        arg("-n --count", "how many future values to predict",
            type=int, default=10, dest="count"),
        arg("-m --modulus", "known LCG modulus (skips modulus recovery)",
            type=_intish, default=None, dest="modulus"),
        arg("-f --file", "read the outputs from a file (line/JSON/CSV)",
            metavar="PATH"),
    ],
    examples=[
        "python3 -m aesop prng --mt -f outputs.txt --count 5",
        "cat rng_dump.txt | aesop prng --mt --count 3   # 624+ getrandbits(32) values",
        "aesop prng --lcg -m 2147483648 1250496027 1116302264 1000676753   # known m",
        "aesop prng --lcg -f lcg_stream.txt --count 8   # unknown m, give 10+ outputs",
    ],
    description="""
        Predict the "random" numbers of statistical (non-cryptographic) PRNGs.
        --mt clones a Mersenne Twister (MT19937 — Python's random, PHP mt_rand,
        many games/tokens): give 624+ consecutive 32-bit outputs and every future
        output is recovered exactly by un-tempering the state.  --lcg recovers a
        linear congruential generator's multiplier a, increment c and (if not
        given) the modulus m from a handful of consecutive outputs, then predicts.
        Feed outputs as positional args, --file (one per line, CSV, or a JSON
        array), or over stdin.  Predicted values are printed with out.raw, one per
        line, so they pipe straight into the next tool.  This does not touch
        secure generators (secrets / os.urandom).
    """,
)
def cmd_prng(args, out) -> int:
    numbers = _gather_numbers(args, out)
    if numbers is None:
        return 2
    if not numbers:
        out.error("no numeric outputs were parsed from the input")
        return 2

    count = max(1, args.count)

    mode = _pick_mode(args, numbers, out)
    if mode == "mt":
        return _do_mt(out, numbers, count)
    return _do_lcg(out, numbers, count, args.modulus)


def _pick_mode(args, numbers: List[int], out) -> str:
    if args.mt and args.lcg:
        out.warn("both --mt and --lcg given; using --mt")
        return "mt"
    if args.mt:
        return "mt"
    if args.lcg:
        return "lcg"
    # Auto: 624+ outputs strongly implies an MT19937 clone; otherwise LCG.
    mode = "mt" if len(numbers) >= _N else "lcg"
    out.info(f"auto-selected --{mode} ({len(numbers)} outputs); pass --mt/--lcg to force")
    return mode


def _do_mt(out, numbers: List[int], count: int) -> int:
    if len(numbers) < _N:
        out.error(f"MT19937 recovery needs at least {_N} consecutive 32-bit outputs, "
                  f"got {len(numbers)}")
        out.hint("MT19937's state is 624 words — you must observe a full state's worth")
        return 1
    bad = [x for x in numbers if x < 0 or x > _MASK32]
    if bad:
        out.error(f"{len(bad)} value(s) are outside the 32-bit range [0, 2^32); "
                  "MT19937 recovery expects raw 32-bit outputs (getrandbits(32))")
        out.hint("if these are truncated (e.g. mod 100) outputs, MT cloning does not apply")
        return 1

    predictor = mt19937_recover(numbers)
    out.success(f"MT19937 state cloned from {len(numbers)} outputs")
    out.keyval(
        [
            ("outputs used", str(_N)),
            ("state words", str(_N)),
            ("predicting", str(count)),
        ],
        title="recovered generator",
    )
    # PRIMARY result: the predicted future outputs, one per line (pipe-friendly).
    for value in predictor.predict_next(count):
        out.raw(str(value))
    return 0


_HOLDOUT = 3   # points held back to cross-validate an auto-recovered modulus


def _cross_validated(numbers: List[int], modulus: Optional[int]) -> bool:
    """Confirm an auto-recovered modulus generalises beyond the fitted points.

    Re-recovers the parameters from all but the last :data:`_HOLDOUT` outputs and
    checks they (a) independently agree with the full-data fit and (b) correctly
    predict the held-out tail.  This is what catches a modulus that overshot to a
    multiple of the true one — it fits the sample yet mispredicts the future.
    A user-supplied modulus is trusted directly and skips this.
    """
    if modulus is not None:
        return True
    if len(numbers) < 6 + _HOLDOUT:
        return False
    try:
        full = lcg_recover(numbers, modulus=None)
        train = lcg_recover(numbers[:-_HOLDOUT], modulus=None)
    except ValueError:
        return False
    if (train.a, train.c, train.m) != (full.a, full.c, full.m):
        return False
    tail = [numbers[-_HOLDOUT + i] % train.m for i in range(_HOLDOUT)]
    return train.predict_next(_HOLDOUT) == tail


def _do_lcg(out, numbers: List[int], count: int, modulus: Optional[int]) -> int:
    if len(numbers) < 3:
        out.error(f"LCG recovery needs at least 3 consecutive outputs, got {len(numbers)}")
        return 1
    try:
        params = lcg_recover(numbers, modulus=modulus)
    except ValueError as exc:
        out.error(str(exc))
        out.hint("provide more consecutive outputs (10+ is comfortable), "
                 "or a known modulus with --modulus")
        return 1

    fits = params.reproduces(numbers)
    confident = fits and _cross_validated(numbers, modulus)

    if not confident:
        # Refuse to emit confidently-wrong predictions.  Almost always too little
        # data: an unknown modulus recovered from a short run can be a multiple of
        # the true one — it fits the sample yet mispredicts the future.
        if not fits:
            out.error("recovered parameters do NOT reproduce the given sequence")
        else:
            out.error("recovered parameters fit the sample but failed cross-validation")
        out.hint("give more consecutive outputs (10+ pins an unknown modulus), "
                 "or supply the true modulus with --modulus")
        out.keyval(
            [("a (best guess)", str(params.a)),
             ("c (best guess)", str(params.c)),
             ("m (best guess)", str(params.m))],
            title="unverified parameters",
        )
        return 1

    if modulus is not None:
        out.success("recovered LCG parameters (verified against the given sequence)")
    else:
        out.success("recovered LCG parameters (cross-validated on held-out outputs)")
    out.keyval(
        [
            ("a (multiplier)", str(params.a)),
            ("c (increment)", str(params.c)),
            ("m (modulus)", str(params.m)),
        ],
        title="recovered LCG",
    )
    # PRIMARY result: the predicted future outputs, one per line (pipe-friendly).
    for value in params.predict_next(count):
        out.raw(str(value))
    return 0

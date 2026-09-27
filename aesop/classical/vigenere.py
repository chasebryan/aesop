"""
aesop.classical.vigenere — the Vigenère polyalphabetic cipher.

For three centuries this was *le chiffre indéchiffrable* — the undecipherable
cipher — because it defeats the single most powerful classical attack: letter
frequency analysis.  A repeating keyword selects a different Caesar shift for
each position, so the same plaintext letter enciphers to many different
ciphertext letters and the tell-tale English frequency spikes are smeared flat.

Like every module in AESOP it keeps two halves apart (see ``caesar.py``):

1. A **programmatic API** of pure functions — :func:`encrypt`, :func:`decrypt`,
   :func:`guess_key_lengths`, :func:`kasiski`, :func:`recover_key`,
   :func:`solve` — that carry the whole attack and are independently testable.
2. A thin **command handler** wired in via :func:`aesop.registry.command` that
   only marshals arguments, loads input and presents results.

The break is the classic two-stage attack: first find the key *length* (Friedman
/ Kasiski), which reduces the polyalphabetic cipher to N independent Caesar
ciphers — one per column — then solve each column by frequency matching.
"""
from __future__ import annotations

import random
from collections import Counter
from typing import List, Tuple

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import (
    chi_squared,
    clean_text,
    default_scorer,
    index_of_coincidence,
    score_text,
)

A = ord("A")
ENGLISH_IC = 0.0667  # expected IC of monoalphabetic English text


# --------------------------------------------------------------------------- #
# Programmatic API — encryption
# --------------------------------------------------------------------------- #
def _clean_key(key: str) -> str:
    """Reduce a keyword to its A-Z shift letters (upper-cased)."""
    return clean_text(key)


def _apply(text: str, key: str, sign: int) -> str:
    """Add (``sign=+1``) or subtract (``sign=-1``) the key's shifts.

    Case and every non-letter are preserved, and the key only advances on
    alphabetic characters — the standard "skip punctuation" convention.
    """
    shifts = [ord(k) - A for k in _clean_key(key)]
    if not shifts:
        raise ValueError("key must contain at least one letter")
    out: List[str] = []
    j = 0
    for ch in text:
        if "a" <= ch <= "z":
            k = sign * shifts[j % len(shifts)]
            out.append(chr((ord(ch) - ord("a") + k) % 26 + ord("a")))
            j += 1
        elif "A" <= ch <= "Z":
            k = sign * shifts[j % len(shifts)]
            out.append(chr((ord(ch) - A + k) % 26 + A))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def encrypt(text: str, key: str) -> str:
    """Encipher ``text`` under the repeating ``key`` (preserves case & layout)."""
    return _apply(text, key, +1)


def decrypt(text: str, key: str) -> str:
    """Decipher ``text`` under the repeating ``key`` (preserves case & layout)."""
    return _apply(text, key, -1)


# --------------------------------------------------------------------------- #
# Programmatic API — key-length detection
# --------------------------------------------------------------------------- #
def _columns(text: str, key_len: int) -> List[str]:
    """Split cleaned ``text`` into ``key_len`` columns (every key_len-th letter)."""
    t = clean_text(text)
    return [t[i::key_len] for i in range(key_len)]


def guess_key_lengths(text: str, max_len: int = 20) -> List[Tuple[int, float]]:
    """Rank candidate key lengths by the Friedman test.

    For each candidate length ``L`` the ciphertext is dealt into ``L`` columns;
    a correct length makes every column a monoalphabetic (Caesar) slice of
    English, whose average Index of Coincidence sits near **0.0667**, while a
    wrong length scrambles the columns towards the random value **0.0385**.

    Returns ``(length, avg_ic)`` pairs sorted best-first (highest average IC).
    The true length — and its multiples — float to the top.
    """
    t = clean_text(text)
    n = len(t)
    if n < 2:
        return [(1, 0.0)]
    upper = max(1, min(max_len, n - 1))
    scored: List[Tuple[int, float]] = []
    for L in range(1, upper + 1):
        ics = [index_of_coincidence(col) for col in _columns(t, L) if len(col) >= 2]
        avg = sum(ics) / len(ics) if ics else 0.0
        scored.append((L, avg))
    scored.sort(key=lambda p: p[1], reverse=True)
    return scored


def kasiski(text: str, min_gram: int = 3, max_gram: int = 5,
            max_factor: int = 20) -> List[Tuple[int, int]]:
    """Kasiski examination: vote for key lengths from repeated-gram spacings.

    Repeated substrings in the ciphertext often line up with the key, so the
    *distance* between repeats tends to be a multiple of the key length.  We
    tally every divisor (2..``max_factor``) of every spacing and return
    ``(factor, votes)`` sorted best-first — strong corroboration for, or a
    tie-breaker against, the Friedman result.
    """
    t = clean_text(text)
    spacings: List[int] = []
    for size in range(min_gram, max_gram + 1):
        last: dict[str, int] = {}
        for i in range(len(t) - size + 1):
            gram = t[i:i + size]
            if gram in last:
                spacings.append(i - last[gram])
            last[gram] = i
    votes: Counter = Counter()
    for d in spacings:
        for f in range(2, min(max_factor, d) + 1):
            if d % f == 0:
                votes[f] += 1
    return votes.most_common()


# --------------------------------------------------------------------------- #
# Programmatic API — key recovery & full solve
# --------------------------------------------------------------------------- #
def _decrypt_clean(clean_cipher: str, shifts: List[int]) -> str:
    """Fast decrypt of an already-clean A-Z string given integer shifts."""
    L = len(shifts)
    return "".join(
        chr((ord(clean_cipher[j]) - A - shifts[j % L]) % 26 + A)
        for j in range(len(clean_cipher))
    )


def _quad_score(clean_upper: str, scorer) -> float:
    """Quadgram log-probability of an already-cleaned uppercase string.

    Skips :func:`aesop.core.score.clean_text` (a regex) on the hot hill-climb
    path; identical to ``scorer.score`` for A-Z-only input.
    """
    if not scorer.loaded or len(clean_upper) < 4:
        return scorer.score(clean_upper)
    log = scorer.log
    floor = scorer.floor
    return sum(log.get(clean_upper[i:i + 4], floor) for i in range(len(clean_upper) - 3))


def _best_column_shift(column: str) -> int:
    """The Caesar shift whose decryption of ``column`` best matches English."""
    def decrypt_by(s: int) -> str:
        return "".join(chr((ord(c) - A - s) % 26 + A) for c in column)

    return min(range(26), key=lambda s: chi_squared(decrypt_by(s)))


def recover_key(text: str, key_len: int) -> str:
    """Recover the keyword assuming a given length.

    Each of the ``key_len`` columns is an independent Caesar cipher; we lock its
    shift with chi-squared against English letter frequencies
    (:func:`aesop.core.score.chi_squared`) and read the shift back as a key
    letter.
    """
    if key_len < 1:
        raise ValueError("key_len must be >= 1")
    return "".join(chr(_best_column_shift(col) + A) for col in _columns(text, key_len))


def _minimal_period(key: str) -> str:
    """Collapse a key that is itself a repetition (``LEMONLEMON`` -> ``LEMON``)."""
    n = len(key)
    for p in range(1, n):
        if n % p == 0 and key[:p] * (n // p) == key:
            return key[:p]
    return key


def _hill_climb(clean_cipher: str, key: str, scorer) -> Tuple[str, float]:
    """Coordinate-ascent on the quadgram score: for each key position try all
    26 letters and keep the best, repeating until no position improves.

    Chi-squared per column is exact on long ciphertext but noisy when each
    column holds only a handful of letters; polishing the whole key against the
    full-text quadgram model escapes those per-column mistakes.
    """
    shifts = [ord(c) - A for c in key]
    best = _quad_score(_decrypt_clean(clean_cipher, shifts), scorer)
    improved = True
    while improved:
        improved = False
        for i in range(len(shifts)):
            keep = shifts[i]
            local_best = keep
            for s in range(26):
                if s == keep:
                    continue
                shifts[i] = s
                sc = _quad_score(_decrypt_clean(clean_cipher, shifts), scorer)
                if sc > best:
                    best, local_best = sc, s
            shifts[i] = local_best
            if local_best != keep:
                improved = True
    return "".join(chr(A + s) for s in shifts), best


def _solve_length(clean_cipher: str, key_len: int, scorer,
                  restarts: int, rng: random.Random) -> Tuple[str, float]:
    """Best key of a fixed length: chi-squared seed plus a few random restarts,
    each polished by :func:`_hill_climb`."""
    seeds = [recover_key(clean_cipher, key_len)]
    for _ in range(restarts):
        seeds.append("".join(chr(A + rng.randrange(26)) for _ in range(key_len)))
    best_key, best_score = "", float("-inf")
    for seed in seeds:
        cand, sc = _hill_climb(clean_cipher, seed, scorer)
        if sc > best_score:
            best_key, best_score = cand, sc
    return best_key, best_score


def _restart_budget(n: int) -> int:
    """Hill-climb restart count scaled by cleaned-text length.

    Short ciphertext has noisy chi-squared columns and needs many restarts to
    escape local optima; long ciphertext is solved by the seed alone.
    """
    if n < 120:
        return 30
    if n < 400:
        return 6
    if n < 2000:
        return 2
    return 0


def solve_with_length(text: str, key_len: int) -> Tuple[str, str]:
    """Best ``(key, plaintext)`` for a *known/forced* key length.

    Uses the same chi-squared seed + quadgram hill-climb (with restarts) as
    :func:`solve`, so forcing the true length yields the true key — not the raw,
    noisy per-column chi-squared guess.
    """
    t = clean_text(text)
    if key_len < 1:
        raise ValueError("key_len must be >= 1")
    if len(t) < 2:
        return ("", text)
    rng = random.Random(0xA3505)
    raw, _ = _solve_length(t, key_len, default_scorer(), _restart_budget(len(t)), rng)
    key = _minimal_period(raw)
    return key, decrypt(text, key)


def _rank_candidate_lengths(text: str, max_len: int, top: int) -> List[int]:
    """Choose which key lengths are worth a full solve.

    The Index of Coincidence alone is decisive on long ciphertext but pure noise
    on short samples (a 10-letter column's IC is meaningless), so we blend three
    signals that no single short text can all fool at once: IC *closeness* to
    English (not merely highest, since short columns overshoot), Kasiski divisor
    votes, and a mild preference for shorter keys (a real period's multiples
    also look monoalphabetic).  Returns candidate lengths best-first.
    """
    fried = dict(guess_key_lengths(text, max_len))
    kas = dict(kasiski(text, max_factor=max_len))
    kmax = max(kas.values()) if kas else 0
    scored: List[Tuple[float, int]] = []
    for L in range(1, max(1, min(max_len, len(text) - 1)) + 1):
        ic = fried.get(L, 0.0)
        ic_score = 1.0 - min(1.0, abs(ic - ENGLISH_IC) / ENGLISH_IC)
        kv = (kas.get(L, 0) / kmax) if kmax else 0.0
        combined = ic_score + 0.5 * kv - 0.01 * L
        scored.append((combined, L))
    scored.sort(key=lambda p: p[0], reverse=True)
    pool = [L for _, L in scored[:max(1, top)]]
    # Guarantee any strongly Kasiski-supported length is in the pool.
    for f, _v in kasiski(text, max_factor=max_len)[:4]:
        if f not in pool:
            pool.append(f)
    return pool


def solve(text: str, max_len: int = 20, top_lengths: int = 5) -> Tuple[str, str, float]:
    """Auto-break: recover ``(key, plaintext, score)`` with no key supplied.

    Gathers candidate key lengths from the Friedman test and Kasiski
    examination, recovers the best key for each (a chi-squared seed refined by
    quadgram hill-climbing with restarts), reduces any repeated key to its
    fundamental period, and keeps the decryption with the best quadgram score
    (:func:`aesop.core.score`) — the same fitness that ranks Caesar shifts.

    Selection uses a small per-key-letter penalty because a too-long key has
    enough free shifts to *overfit* a short ciphertext and win on raw score;
    the penalty (and the length ranking above) keep the genuine, shorter key on
    top without hurting long ciphertext, where the real key wins outright.
    """
    t = clean_text(text)
    if len(t) < 2:
        return ("", text, score_text(text))

    candidates = _rank_candidate_lengths(t, max_len, top_lengths)

    # Random restarts rescue short ciphertext (where a single seed sticks in a
    # local optimum); long ciphertext is nailed by the seed alone, so scale the
    # budget down to keep large inputs fast.  Fixed seed => repeatable results.
    restarts = _restart_budget(len(t))
    rng = random.Random(0xA3505)
    scorer = default_scorer()
    penalty = 0.08  # per key letter, applied to the per-quadgram (normalized) score

    best: Tuple[str, str, float] = ("", text, float("-inf"))
    best_adj = float("-inf")
    seen: set[str] = set()
    for rank, L in enumerate(candidates):
        # The best-ranked lengths earn the full restart budget; lower-ranked
        # ones get the (cheap) chi-squared seed only, keeping large inputs fast.
        r = restarts if rank < 3 else 0
        raw_key, _ = _solve_length(t, L, scorer, r, rng)
        key = _minimal_period(raw_key)
        if not key or key in seen:
            continue
        seen.add(key)
        plain = decrypt(text, key)
        sc = scorer.score(plain)
        adj = scorer.score_normalized(plain) - penalty * len(key)
        if adj > best_adj:
            best_adj = adj
            best = (key, plain, sc)
    return best


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "vigenere",
    group="classical",
    summary="Break or apply a Vigenère (repeating-key) cipher",
    manual="vigenere",
    aliases=["vig"],
    args=io_args(
        positional="text",
        positional_help="the ciphertext to break (or plaintext to encode)",
    ) + [
        arg("-k --key", "known keyword: decrypt with it (or encrypt with --encode)"),
        arg("--encode", "encrypt with --key instead of breaking", action="store_true"),
        arg("--key-length", "force a specific key length instead of detecting it",
            type=int, metavar="N"),
        arg("--top", "how many candidate key lengths to show when auto-solving",
            type=int, default=5),
    ],
    examples=[
        "aesop vigenere 'Rijvs, Uytestj!'                     # auto-break",
        "aesop vigenere --encode -k lemon 'Attack at dawn'    # encrypt",
        "aesop vigenere -k lemon 'Ttfnk ff oaie'              # decrypt with key",
        "echo 'Rijvs Uytestj' | aesop vigenere --key-length 5 # force length",
    ],
    description="""
        Vigenère enciphers with a repeating keyword — one Caesar shift per key
        letter — which flattens letter frequencies and long defeated
        cryptanalysts.  With --key the transform is applied directly (add
        --encode to encipher).  Without a key, AESOP breaks it automatically:
        it finds the key length with the Friedman / Index-of-Coincidence test
        (corroborated by Kasiski), locks each column's Caesar shift by
        chi-squared, then ranks the result with quadgram scoring — printing the
        recovered key and plaintext.
    """,
)
def cmd_vigenere(args, out) -> int:
    key = getattr(args, "key", None)

    # --- encode: plaintext in, ciphertext out (never sniff prose) ----------- #
    if args.encode:
        if not key:
            out.error("--encode needs a key (-k/--key)")
            return 2
        inp = io.load(args, encoding="raw")
        try:
            cipher = encrypt(inp.text, key)
        except ValueError as exc:
            out.error(str(exc))
            return 2
        out.success(f"encrypted with key {_clean_key(key)}")
        out.raw(cipher)
        return 0

    inp = io.load(args)
    text = inp.text

    # --- decrypt with a known key ------------------------------------------- #
    if key:
        try:
            plain = decrypt(text, key)
        except ValueError as exc:
            out.error(str(exc))
            return 2
        out.success(f"decrypted with key {_clean_key(key)}")
        out.raw(plain)
        return 0

    # --- forced key length: detect the keyword at that length --------------- #
    if args.key_length is not None:
        if args.key_length < 1:
            out.error("--key-length must be >= 1")
            return 2
        rec, plain = solve_with_length(text, args.key_length)
        if not rec:
            out.error("need at least a few letters of ciphertext")
            return 1
        out.success(f"recovered key {rec} (length {len(rec)})")
        out.raw(plain)
        return 0

    # --- full auto-solve ---------------------------------------------------- #
    if len(clean_text(text)) < 4:
        out.error("need at least a few letters of ciphertext to auto-solve")
        return 2

    key_out, plain, _score = solve(text)
    if not key_out:
        out.error("could not recover a key")
        return 1
    out.success(f"recovered key {key_out} (length {len(key_out)})")
    out.raw(plain)

    # Diagnostics: the key-length evidence that drove the choice.
    top = max(1, args.top)
    lengths = guess_key_lengths(text)[:top]
    kas = dict(kasiski(text))
    out.print()
    out.table(
        ["key len", "avg IC", "Δ from English", "Kasiski votes"],
        [
            (L, f"{ic:.4f}", f"{abs(ic - ENGLISH_IC):.4f}", kas.get(L, 0))
            for L, ic in lengths
        ],
        title="key-length evidence (English IC ≈ 0.0667)",
    )
    return 0

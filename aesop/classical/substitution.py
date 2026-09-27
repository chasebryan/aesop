"""
aesop.classical.substitution — general monoalphabetic substitution.

A substitution cipher replaces each plaintext letter with a fixed, but
otherwise arbitrary, ciphertext letter.  Unlike Caesar (which is one of only 26
shifts) the key here is an *arbitrary permutation* of the 26-letter alphabet, so
the keyspace is a staggering ``26! ≈ 4 × 10²⁶`` — far too large to brute force.

Yet the cipher is famously breakable, because it does nothing to hide the
*statistics* of the language: 'E' is still the most common letter, 'THE' is
still the most common trigram, only wearing a mask.  AESOP tears the mask off
with **hill-climbing on a quadgram fitness function** — the same idea a
newspaper cryptogram solver applies by hand, mechanised.

Like every AESOP module this file keeps two halves apart:

1. A **programmatic API** on plain ``str`` — :func:`apply_key`, :func:`decrypt`,
   :func:`invert_key`, :func:`solve` — that is pure and importable.
2. A thin **CLI handler** (:func:`cmd_substitution`) that only marshals args,
   loads input and presents results.
"""
from __future__ import annotations

import random
from collections import Counter
from typing import Callable, List, Tuple

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import clean_text, default_scorer, score_text

A = ord("A")
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# English letters ordered by descending frequency (ETAOIN SHRDLU ...).  Used to
# seed the hill-climb with a sensible first guess.
_ENGLISH_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"


# --------------------------------------------------------------------------- #
# Programmatic API
# --------------------------------------------------------------------------- #
def normalize_key(key: str) -> str:
    """Validate and canonicalise a substitution key.

    Accepts a 26-character string (case-insensitive, surrounding whitespace
    ignored) that is a permutation of A–Z.  Returns it upper-cased.  Raises
    ``ValueError`` for anything that is not a genuine permutation, because a
    substitution key must be a bijection for decryption to be well defined.
    """
    k = "".join(key.split()).upper()
    if len(k) != 26 or set(k) != set(ALPHABET):
        raise ValueError(
            "key must be a permutation of the 26 letters A–Z "
            f"(got {len(k)} chars: {key!r})"
        )
    return k


def apply_key(text: str, key: str) -> str:
    """Encrypt ``text`` with substitution ``key``.

    ``key`` is a 26-character permutation: plaintext ``A`` becomes ``key[0]``,
    ``B`` becomes ``key[1]``, and so on.  Case is preserved and every
    non-letter passes through untouched.
    """
    table = normalize_key(key)
    out: List[str] = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(table[ord(ch) - A])
        elif "a" <= ch <= "z":
            out.append(table[ord(ch) - ord("a")].lower())
        else:
            out.append(ch)
    return "".join(out)


def invert_key(key: str) -> str:
    """Return the inverse permutation of ``key`` (the decryption key)."""
    k = normalize_key(key)
    inv = [""] * 26
    for i, ch in enumerate(k):
        inv[ord(ch) - A] = chr(A + i)
    return "".join(inv)


def decrypt(text: str, key: str) -> str:
    """Decrypt ``text`` that was encrypted with substitution ``key``.

    Applies the inverse mapping, so ``decrypt(apply_key(pt, k), k) == pt``.
    """
    return apply_key(text, invert_key(key))


def _freq_seed_key(cipher_clean: str) -> str:
    """Frequency-matched *decryption* key: cipher letter → plaintext guess.

    The most frequent ciphertext letter is guessed to be 'E', the next 'T', and
    so on down :data:`_ENGLISH_ORDER`.  Returned as a 26-char table indexed by
    ciphertext letter (index 0 = what 'A' decrypts to).
    """
    freq = Counter(cipher_clean)
    # Sort by descending count, then alphabetically for determinism.
    by_freq = sorted(ALPHABET, key=lambda c: (-freq.get(c, 0), c))
    table = [""] * 26
    for rank, cipher_letter in enumerate(by_freq):
        table[ord(cipher_letter) - A] = _ENGLISH_ORDER[rank]
    return "".join(table)


def _decode_indices(indices: List[int], dkey: str) -> str:
    """Apply decryption table ``dkey`` to pre-computed cipher letter indices."""
    return "".join([dkey[i] for i in indices])


def _fast_scorer() -> Callable[[str], float]:
    """A scorer specialised for already-cleaned upper-case text.

    Bypasses :func:`clean_text` on every call (the hot path runs it tens of
    thousands of times).  Falls back to the generic scorer if the quadgram
    model is unavailable so behaviour never depends on the data file existing.
    """
    scorer = default_scorer()
    if scorer.loaded:
        log = scorer.log
        floor = scorer.floor

        def score(s: str) -> float:
            if len(s) < 4:
                return -999.0 * (4 - len(s))
            return sum([log.get(s[i : i + 4], floor) for i in range(len(s) - 3)])

        return score
    return scorer.score


def solve(
    text: str,
    restarts: int = 30,
    iterations: int = 4000,
    seed: int = 0,
) -> Tuple[str, str, float]:
    """Recover the key of a monoalphabetic substitution cipher.

    Runs **hill-climbing** over the space of decryption keys, scoring each
    candidate plaintext with quadgram log-probabilities
    (:func:`aesop.core.score.default_scorer`):

    * Restart 0 starts from a **frequency-matched** key (ETAOIN heuristic).
      Later restarts alternate between *iterated local search* (perturb the best
      key so far with a few random swaps) and a fresh random permutation, to
      escape local optima.  Randomness is deterministic — each restart *r* uses
      ``random.Random(seed + r)`` — so results are reproducible.
    * Each restart climbs by sweeping over every pair of key letters, keeping any
      swap that *raises* the quadgram score of the decrypted text, and repeating
      the sweep until it makes no further progress (``iterations`` bounds the
      evaluations per restart).

    Returns ``(key, plaintext, score)`` where ``key`` is the recovered
    *encryption* key (so ``decrypt(text, key)`` reproduces ``plaintext``) and
    ``score`` is the quadgram fitness of the recovered plaintext (higher is more
    English-like).

    A few hundred letters of ciphertext are enough to recover the key almost
    exactly; shorter texts leave rare letters (J, Q, X, Z) ambiguous.
    """
    restarts = max(1, restarts)
    iterations = max(1, iterations)
    cipher_clean = clean_text(text)

    # Nothing to work with — return the identity key.
    if len(cipher_clean) < 4:
        return ALPHABET, apply_key(text, ALPHABET), score_text(text)

    indices = [ord(c) - A for c in cipher_clean]
    score = _fast_scorer()

    best_key = ALPHABET  # decryption key (cipher → plain)
    best_score = float("-inf")

    for r in range(restarts):
        rng = random.Random(seed + r)
        if r == 0:
            # First restart: the frequency-matched seed.
            parent = list(_freq_seed_key(cipher_clean))
        elif best_score > float("-inf") and r % 2 == 0:
            # Iterated local search: perturb the best key found so far with a
            # few random swaps, then climb again — escapes local optima far more
            # reliably than blind random restarts alone.
            parent = list(best_key)
            for _ in range(rng.randint(2, 5)):
                a, b = rng.randrange(26), rng.randrange(26)
                parent[a], parent[b] = parent[b], parent[a]
        else:
            # A fresh random permutation, for genuine diversity.
            parent = list(ALPHABET)
            rng.shuffle(parent)

        parent_score = score(_decode_indices(indices, "".join(parent)))

        # Systematic hill-climb: sweep over every pair of key letters, keeping
        # any swap that improves the score, and repeat until a whole sweep makes
        # no progress (a thorough local optimum).  Far more reliable than random
        # swap sampling.  ``iterations`` caps the total evaluations per restart.
        evals = 0
        improved = True
        while improved and evals < iterations:
            improved = False
            for i in range(25):
                for j in range(i + 1, 26):
                    parent[i], parent[j] = parent[j], parent[i]
                    child_score = score(_decode_indices(indices, "".join(parent)))
                    evals += 1
                    if child_score > parent_score:
                        parent_score = child_score
                        improved = True
                    else:
                        parent[i], parent[j] = parent[j], parent[i]  # revert
            if evals >= iterations:
                break

        if parent_score > best_score:
            best_score = parent_score
            best_key = "".join(parent)

    # best_key is a decryption table (cipher → plain): apply it to recover the
    # plaintext.  The reported key is its inverse (the encryption key), so
    # callers can round-trip with apply_key / decrypt.
    plaintext = apply_key(text, best_key)
    enc_key = invert_key(best_key)
    # Report the score against the proper (quadgram) scorer for consistency.
    return enc_key, plaintext, score_text(plaintext)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "substitution",
    group="classical",
    summary="Break or apply a general monoalphabetic substitution cipher",
    manual="substitution",
    aliases=["subst", "mono"],
    args=io_args(
        positional="text",
        positional_help="the ciphertext to break (or plaintext to encode)",
    )
    + [
        arg("-k --key", "26-letter substitution key (A→key[0], …); decode/encode with it"),
        arg("--encode", "encode/encrypt with --key instead of breaking", action="store_true"),
        arg("--restarts", "hill-climb restarts when auto-solving", type=int, default=30),
        arg("--iterations", "max key-swap evaluations per restart (sweeps stop early once converged)",
            type=int, default=4000),
    ],
    examples=[
        "aesop substitution -f cryptogram.txt            # auto-solve, no key needed",
        "aesop substitution --restarts 40 --iterations 6000 -f hard_cryptogram.txt",
        "aesop substitution --encode -k QWERTYUIOPASDFGHJKLZXCVBNM 'Attack at dawn'",
        "aesop substitution -k QWERTYUIOPASDFGHJKLZXCVBNM 'Qzzqea qz rqvf'",
    ],
    description="""
        A monoalphabetic substitution cipher maps each letter to a fixed
        replacement via an arbitrary 26-letter permutation — a keyspace of 26!,
        hopeless to brute force.  With --key the transform is applied directly
        (add --encode to encrypt); without a key, AESOP recovers it by
        hill-climbing on quadgram statistics, the way a cryptogram enthusiast
        solves a newspaper puzzle, and prints both the key and the plaintext.
        A few hundred letters of ciphertext are enough for a near-perfect break.
    """,
)
def cmd_substitution(args, out) -> int:
    # Encoding takes plaintext verbatim; never sniff (prose can look like base64).
    inp = io.load(args, encoding="raw" if args.encode else None)
    text = inp.text

    # --- Known-key paths -------------------------------------------------- #
    if args.encode:
        if not args.key:
            out.error("--encode needs a key; pass -k/--key <26-letter permutation>")
            return 2
        try:
            key = normalize_key(args.key)
        except ValueError as exc:
            out.error(str(exc))
            return 2
        out.raw(apply_key(text, key))
        _show_key(out, key, title="substitution key (plaintext → ciphertext)")
        return 0

    if args.key:
        try:
            key = normalize_key(args.key)
        except ValueError as exc:
            out.error(str(exc))
            return 2
        out.raw(decrypt(text, key))
        _show_key(out, key, title="substitution key (plaintext → ciphertext)")
        return 0

    # --- Auto-solve ------------------------------------------------------- #
    letters = clean_text(text)
    if len(letters) < 4:
        out.error("need at least a few letters of ciphertext to solve")
        return 2
    if len(letters) < 100:
        out.warn(f"only {len(letters)} letters — short ciphertext may not fully resolve "
                 "(rare letters stay ambiguous)")

    key, plaintext, score = solve(
        text, restarts=max(1, args.restarts), iterations=max(1, args.iterations)
    )
    out.success(f"best guess — quadgram score {score:.1f}")
    out.raw(plaintext)
    out.print()
    _show_key(out, key, title="recovered key (plaintext → ciphertext)")
    out.hint(f"reuse it:  aesop substitution -k {key} <ciphertext>")
    return 0


def _show_key(out, key: str, title: str) -> None:
    """Render a substitution key as an aligned plaintext/ciphertext mapping."""
    out.keyval(
        [("plaintext ", ALPHABET), ("ciphertext", key)],
        title=title,
    )

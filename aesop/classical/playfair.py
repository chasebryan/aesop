"""
aesop.classical.playfair — the Playfair digraph cipher.

Playfair encrypts *pairs* of letters against a 5×5 key square (I and J share a
cell), which flattens single-letter frequency and defeats a Caesar- or
substitution-style solver.  It was the first practical digraph cipher and saw
field service through both World Wars.

Like every AESOP technique module, this file keeps two halves apart:

1. A **programmatic API** — pure functions on ``str`` (:func:`build_square`,
   :func:`encrypt`, :func:`decrypt`, :func:`solve`, :func:`solve_keyword`,
   :func:`auto_solve`) that are importable and unit-testable.
2. A thin **command handler** wired into the CLI via
   :func:`aesop.registry.command`, which only marshals arguments, loads input
   and presents results through ``out``.

Breaking an unknown key uses two complementary strategies:

* :func:`solve` — **simulated annealing / hill-climbing** over the 25-letter
  square (swap letters / rows / columns), scoring each candidate decryption with
  the shared English quadgram model.  Randomness is seeded deterministically with
  :class:`random.Random`, so a run is reproducible.  This is the general attack,
  but it needs a strong language model and a lot of ciphertext to reliably beat
  the huge (25!) key space.
* :func:`solve_keyword` — a **keyword dictionary attack**.  Real Playfair keys
  are almost always English key phrases, so trying every dictionary word as the
  key, decrypting and scoring, recovers the message near-instantly for the common
  case.  This is the workhorse the CLI reaches for first.

The fox does not wrestle the whole alphabet when a known word opens the gate.
"""
from __future__ import annotations

import math
import os
import random
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import clean_text, default_scorer

# The 25-letter Playfair alphabet: J is folded onto I, so it never appears.
ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

# Default filler to separate a doubled pair or pad an odd tail, plus the
# alternate used when the letter needing a filler *is* the default filler.
FILLER = "X"
ALT_FILLER = "Q"

# Standard locations for an English word list, tried in order (optional).
_WORDLIST_PATHS = (
    "/usr/share/dict/american-english",
    "/usr/share/dict/british-english",
    "/usr/share/dict/words",
    "/usr/share/dict/cracklib-small",
    "/usr/dict/words",
)


# --------------------------------------------------------------------------- #
# Key square
# --------------------------------------------------------------------------- #
def build_square(key: str) -> str:
    """Build the 25-letter key square (row-major) from a key phrase.

    The key's letters are taken in order, upper-cased, with ``J`` folded to
    ``I`` and duplicates dropped; the remaining alphabet then fills the empty
    cells.  The result is a 25-character string read left-to-right, top-to-bottom.

    >>> build_square("PLAYFAIR EXAMPLE")
    'PLAYFIREXMBCDGHKNOQSTUVWZ'
    """
    seen: List[str] = []
    for ch in (key or "").upper():
        if ch == "J":
            ch = "I"
        if "A" <= ch <= "Z" and ch != "J" and ch not in seen:
            seen.append(ch)
    for ch in ALPHABET:
        if ch not in seen:
            seen.append(ch)
    return "".join(seen)


def format_square(square: str) -> str:
    """Render a 25-letter square as five space-separated rows for display."""
    return "\n".join(" ".join(square[r * 5:r * 5 + 5]) for r in range(5))


def _positions(square: str) -> Dict[str, Tuple[int, int]]:
    """Map each letter to its ``(row, col)`` in the square."""
    return {ch: (i // 5, i % 5) for i, ch in enumerate(square)}


# --------------------------------------------------------------------------- #
# Text preparation
# --------------------------------------------------------------------------- #
def _prepare(text: str) -> str:
    """Upper-case, strip non-letters and fold ``J`` onto ``I``."""
    out: List[str] = []
    for ch in text.upper():
        if ch == "J":
            ch = "I"
        if "A" <= ch <= "Z" and ch != "J":
            out.append(ch)
    return "".join(out)


def digraphs(text: str, filler: str = FILLER) -> List[str]:
    """Split prepared ``text`` into Playfair digraphs.

    A filler is inserted between a doubled pair, and a lone trailing letter is
    padded, so every returned element is a two-letter, non-doubled digraph.  If
    the letter that needs a filler already equals ``filler``, the alternate
    filler is used so the inserted pair never doubles either.
    """
    letters = _prepare(text)
    pairs: List[str] = []
    i, n = 0, len(letters)
    while i < n:
        a = letters[i]
        b = letters[i + 1] if i + 1 < n else ""
        if b == "" or a == b:
            f = filler if a != filler else ALT_FILLER
            pairs.append(a + f)
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def prepared_plaintext(text: str, filler: str = FILLER) -> str:
    """The exact letters that encryption consumes (fillers inserted, padded).

    Decrypting a ciphertext reproduces *this* string, not the raw original,
    because Playfair cannot know which fillers were inserted.
    """
    return "".join(digraphs(text, filler))


# --------------------------------------------------------------------------- #
# Core transform
# --------------------------------------------------------------------------- #
def _shift_pair(a: str, b: str, square: str, pos: Dict[str, Tuple[int, int]],
                direction: int) -> str:
    """Transform one digraph. ``direction`` is +1 to encrypt, -1 to decrypt."""
    ra, ca = pos[a]
    rb, cb = pos[b]
    if ra == rb:  # same row -> take the neighbour to the right / left
        ca = (ca + direction) % 5
        cb = (cb + direction) % 5
    elif ca == cb:  # same column -> take the neighbour below / above
        ra = (ra + direction) % 5
        rb = (rb + direction) % 5
    else:  # rectangle -> swap columns (self-inverse)
        ca, cb = cb, ca
    return square[ra * 5 + ca] + square[rb * 5 + cb]


def _apply(letters: str, square: str, direction: int) -> str:
    """Apply the transform to already-paired ``letters`` against ``square``."""
    pos = _positions(square)
    out: List[str] = []
    for i in range(0, len(letters) - 1, 2):
        out.append(_shift_pair(letters[i], letters[i + 1], square, pos, direction))
    if len(letters) % 2:  # stray letter (only for malformed ciphertext)
        out.append(letters[-1])
    return "".join(out)


def encrypt(text: str, key: str, filler: str = FILLER) -> str:
    """Encrypt ``text`` under Playfair with ``key``.

    Non-letters are dropped, ``J`` becomes ``I``, doubles are separated with a
    filler and an odd tail is padded.

    >>> encrypt("Hide the gold in the tree stump", "PLAYFAIR EXAMPLE")
    'BMODZBXDNABEKUDMUIXMMOUVIF'
    """
    square = build_square(key)
    return _apply("".join(digraphs(text, filler)), square, +1)


def decrypt(text: str, key: str) -> str:
    """Decrypt ciphertext ``text`` under Playfair with ``key``.

    The result still contains any filler letters that encryption inserted; it
    equals :func:`prepared_plaintext` of the original message.

    >>> decrypt("BMODZBXDNABEKUDMUIXMMOUVIF", "PLAYFAIR EXAMPLE")
    'HIDETHEGOLDINTHETREXESTUMP'
    """
    square = build_square(key)
    return _apply(_prepare(text), square, -1)


# --------------------------------------------------------------------------- #
# Scoring helpers (fast path over the shared quadgram model)
# --------------------------------------------------------------------------- #
def _make_scorer():
    """Return ``(score_fn, normalize)`` bound to the shared quadgram model.

    ``score_fn`` takes an already-clean A–Z string (as produced by decryption)
    and returns its quadgram log-probability; higher is better.  ``normalize``
    turns a raw score into a per-quadgram average, comparable across lengths.
    """
    scorer = default_scorer()
    if scorer.loaded:
        log, floor = scorer.log, scorer.floor

        def score_fn(s: str) -> float:
            g = log.get
            return sum(g(s[i:i + 4], floor) for i in range(len(s) - 3))
    else:  # pragma: no cover - only when the quadgram model is missing
        def score_fn(s: str) -> float:
            return scorer.score(s)

    def normalize(raw: float, n: int) -> float:
        return raw / max(1, n - 3)

    return score_fn, normalize


# A per-quadgram average above this reads as English rather than noise (the
# bundled model scores clean English near -5.2 and random text near -7.7).
_READABLE_THRESHOLD = -6.0


# --------------------------------------------------------------------------- #
# Solutions
# --------------------------------------------------------------------------- #
@dataclass
class Solution:
    """One recovered key + decryption, with its fitness score."""

    key: str          # the 25-letter square (row-major)
    plaintext: str    # decryption under that square
    score: float      # quadgram log-probability (higher is better)
    label: str = ""   # how it was found, e.g. "keyword:MONARCHY" or "anneal"

    def __iter__(self):  # allow tuple unpacking
        return iter((self.key, self.plaintext, self.score))


def _dedup_best(cands: Iterable[Solution], top: int) -> List[Solution]:
    """Sort by score (best first), drop duplicate plaintexts, keep ``top``."""
    out: List[Solution] = []
    seen = set()
    for s in sorted(cands, key=lambda r: r.score, reverse=True):
        if s.plaintext in seen:
            continue
        seen.add(s.plaintext)
        out.append(s)
        if len(out) >= max(1, top):
            break
    return out


# --------------------------------------------------------------------------- #
# Simulated-annealing solver (general attack over the 25! key space)
# --------------------------------------------------------------------------- #
def _neighbour(square: str, rng: random.Random) -> str:
    """A near-by key square: swap two letters, rows, or columns (weighted)."""
    s = list(square)
    r = rng.random()
    if r < 0.90:  # swap two random cells — the workhorse move
        i, j = rng.randrange(25), rng.randrange(25)
        s[i], s[j] = s[j], s[i]
    elif r < 0.92:  # swap two rows
        a, b = rng.randrange(5), rng.randrange(5)
        for c in range(5):
            s[a * 5 + c], s[b * 5 + c] = s[b * 5 + c], s[a * 5 + c]
    elif r < 0.94:  # swap two columns
        a, b = rng.randrange(5), rng.randrange(5)
        for row in range(5):
            s[row * 5 + a], s[row * 5 + b] = s[row * 5 + b], s[row * 5 + a]
    elif r < 0.96:  # reverse the order of the rows
        s = [ch for row in reversed([s[k * 5:k * 5 + 5] for k in range(5)]) for ch in row]
    elif r < 0.98:  # reverse each row (flip columns)
        for k in range(5):
            s[k * 5:k * 5 + 5] = s[k * 5:k * 5 + 5][::-1]
    else:  # reverse the whole square
        s = s[::-1]
    return "".join(s)


def _greedy_polish(letters: str, square: str, score_fn) -> Tuple[str, float]:
    """Steepest-ascent single-swap hill-climb until no swap improves the score."""
    best_key = square
    best_score = score_fn(_apply(letters, best_key, -1))
    improved = True
    while improved:
        improved = False
        for i in range(25):
            for j in range(i + 1, 25):
                s = list(best_key)
                s[i], s[j] = s[j], s[i]
                cand = "".join(s)
                sc = score_fn(_apply(letters, cand, -1))
                if sc > best_score:
                    best_key, best_score = cand, sc
                    improved = True
    return best_key, best_score


def _anneal(letters: str, score_fn, rng: random.Random,
            iterations: int, t0: float, t1: float,
            start: Optional[str] = None) -> Solution:
    """One simulated-annealing run; returns its best square + decryption."""
    if start is None:
        current = list(ALPHABET)
        rng.shuffle(current)
        current = "".join(current)
    else:
        current = start
    cur_score = score_fn(_apply(letters, current, -1))
    best_key, best_score = current, cur_score

    cooling = (t1 / t0) ** (1.0 / max(1, iterations))
    temp = t0
    for _ in range(iterations):
        cand = _neighbour(current, rng)
        cand_score = score_fn(_apply(letters, cand, -1))
        delta = cand_score - cur_score
        if delta > 0 or rng.random() < math.exp(delta / temp):
            current, cur_score = cand, cand_score
            if cur_score > best_score:
                best_key, best_score = current, cur_score
        temp *= cooling

    best_key, best_score = _greedy_polish(letters, best_key, score_fn)
    return Solution(best_key, _apply(letters, best_key, -1), best_score, "anneal")


def solve(text: str, *, restarts: int = 14, iterations: int = 6000,
          t0: float = 8.0, t1: float = 0.2, seed: int = 0,
          top: int = 1) -> List[Solution]:
    """Recover the key square from ciphertext ``text`` by simulated annealing.

    Runs ``restarts`` independent annealing schedules, each seeded with
    ``random.Random(seed + i)`` so the search is fully deterministic, and returns
    the best ``top`` distinct solutions (highest quadgram score first).

    Simulated annealing must climb the enormous 25! key space guided only by the
    language model, so it is the *general* attack but not a magic one: it wants a
    strong quadgram model and a lot of ciphertext.  For the usual case of a
    word-based key, :func:`solve_keyword` is far faster and more reliable — the
    CLI tries it first.  More ``restarts``/``iterations`` trade time for odds.
    """
    letters = _prepare(text)
    if len(letters) % 2:  # pairing needs an even count
        letters = letters[:-1]
    if len(letters) < 4:
        return [Solution(build_square(""), decrypt(text, ""), float("-inf"), "anneal")]

    score_fn, _ = _make_scorer()
    results = [
        _anneal(letters, score_fn, random.Random(seed + i), iterations, t0, t1)
        for i in range(max(1, restarts))
    ]
    return _dedup_best(results, top)


# --------------------------------------------------------------------------- #
# Keyword dictionary attack (fast, reliable for word-based keys)
# --------------------------------------------------------------------------- #
def load_wordlist(path: Optional[str] = None) -> List[str]:
    """Load an English word list for the keyword attack.

    Tries ``path`` first, then the standard ``/usr/share/dict`` locations.
    Returns an empty list if none is available — callers degrade gracefully.
    """
    candidates = [path] if path else []
    candidates += list(_WORDLIST_PATHS)
    for p in candidates:
        if not p:
            continue
        try:
            with open(p, "r", encoding="latin-1") as fh:
                return [ln.strip() for ln in fh if ln.strip()]
        except OSError:
            continue
    return []


def solve_keyword(text: str, *, words: Optional[Sequence[str]] = None,
                  wordlist_path: Optional[str] = None, top: int = 1,
                  polish: bool = True) -> List[Solution]:
    """Break Playfair by trying each dictionary word as the key phrase.

    Every candidate word becomes a key square (deduplicated); the ciphertext is
    decrypted and scored with the quadgram model, and the best keys are kept.
    When ``polish`` is set, the single best square is refined by a greedy
    single-swap hill-climb, which repairs a key that is *almost* the true phrase.

    Returns an empty list if no word list is available and none was supplied.
    """
    letters = _prepare(text)
    if len(letters) % 2:
        letters = letters[:-1]
    if len(letters) < 4:
        return []

    if words is None:
        words = load_wordlist(wordlist_path)
    if not words:
        return []

    score_fn, _ = _make_scorer()
    best_by_square: Dict[str, float] = {}
    for w in words:
        u = "".join(ch for ch in w.upper() if ("A" <= ch <= "Z"))
        if len(u) < 3:
            continue
        sq = build_square(u)
        if sq in best_by_square:
            continue
        best_by_square[sq] = score_fn(_apply(letters, sq, -1))

    if not best_by_square:
        return []

    ranked = sorted(best_by_square.items(), key=lambda kv: kv[1], reverse=True)
    cands = [Solution(sq, _apply(letters, sq, -1), sc, "keyword")
             for sq, sc in ranked[: max(1, top) * 4]]

    if polish and cands:
        pk, ps = _greedy_polish(letters, cands[0].key, score_fn)
        if ps > cands[0].score:
            cands.append(Solution(pk, _apply(letters, pk, -1), ps, "keyword+polish"))
    return _dedup_best(cands, top)


# --------------------------------------------------------------------------- #
# Orchestrated auto-solve: keyword attack first, annealing as a fallback
# --------------------------------------------------------------------------- #
def auto_solve(text: str, *, wordlist_path: Optional[str] = None,
               restarts: int = 14, iterations: int = 6000, seed: int = 0,
               top: int = 1, use_keyword: bool = True,
               use_anneal: Optional[bool] = None) -> List[Solution]:
    """Best-effort break: keyword dictionary attack, then annealing if needed.

    Runs :func:`solve_keyword` first (fast, reliable for real key phrases).  If
    that already yields readable English, annealing is skipped; otherwise (or when
    ``use_anneal`` is forced on) :func:`solve` supplements it.  Returns the best
    ``top`` distinct candidates across both strategies.
    """
    _, normalize = _make_scorer()
    letters = _prepare(text)
    if len(letters) % 2:
        letters = letters[:-1]
    n = len(letters)

    cands: List[Solution] = []
    keyword_readable = False
    if use_keyword:
        kw = solve_keyword(text, wordlist_path=wordlist_path, top=max(3, top))
        cands.extend(kw)
        if kw and normalize(kw[0].score, n) > _READABLE_THRESHOLD:
            keyword_readable = True

    run_anneal = use_anneal if use_anneal is not None else (not keyword_readable)
    if run_anneal:
        cands.extend(solve(text, restarts=restarts, iterations=iterations,
                           seed=seed, top=max(3, top)))

    if not cands:  # no word list *and* annealing disabled — fall back to annealing
        cands = solve(text, restarts=restarts, iterations=iterations,
                      seed=seed, top=max(3, top))
    return _dedup_best(cands, top)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "playfair",
    group="classical",
    summary="Break or apply a Playfair digraph cipher",
    manual="playfair",
    aliases=["pf"],
    args=io_args(positional="text",
                 positional_help="ciphertext to break (or plaintext to encrypt with -k --encode)") + [
        arg("-k --key", "key phrase for the 5x5 square (required with --encode/--decode)"),
        arg("--encode", "encrypt the input with --key instead of breaking", action="store_true"),
        arg("--decode", "decrypt the input with --key instead of breaking", action="store_true"),
        arg("--wordlist", "word list for the keyword attack (default: system dictionary)",
            metavar="PATH"),
        arg("--sa-only", "skip the keyword attack; use simulated annealing only",
            action="store_true"),
        arg("--restarts", "annealing restarts when auto-solving", type=int, default=14),
        arg("--iters", "annealing iterations per restart", type=int, default=6000),
        arg("--seed", "base RNG seed for the deterministic search", type=int, default=0),
        arg("--top", "how many candidate keys to show when auto-solving", type=int, default=1),
        arg("--show-square", "also print the key square used/recovered", action="store_true"),
    ],
    examples=[
        "aesop playfair --encode -k 'PLAYFAIR EXAMPLE' 'Hide the gold in the tree stump'",
        "aesop playfair --decode -k 'PLAYFAIR EXAMPLE' BMODZBXDNABEKUDMUIXMMOUVIF",
        "aesop playfair 'GATLMZCLRQXA...'   # auto-solve: keyword attack, then annealing",
        "echo <ciphertext> | aesop playfair --show-square",
    ],
    description="""
        Playfair encrypts letters in pairs against a 5x5 key square (I/J share a
        cell), which flattens single-letter frequencies and defeats a Caesar or
        substitution solver.  With --key plus --encode/--decode the transform is
        applied directly.  Without a key, AESOP breaks it: it first runs a keyword
        dictionary attack (real Playfair keys are English phrases, so this cracks
        the common case in seconds), and falls back to simulated annealing over
        the key square — swapping letters, rows and columns and scoring each
        decryption with the English quadgram model — for non-dictionary keys.  The
        search is seeded deterministically, so runs are reproducible.  Annealing
        needs plenty of ciphertext; raise --restarts/--iters if it comes back
        garbled, or supply a richer --wordlist.
    """,
)
def cmd_playfair(args, out) -> int:
    if args.encode or args.decode:
        if not args.key:
            out.error("a key is required with --encode/--decode (use -k/--key)")
            return 2
        # Encoding takes literal plaintext; never sniff it as hex/base64.
        inp = io.load(args, encoding="raw" if args.encode else None)
        square = build_square(args.key)
        result = encrypt(inp.text, args.key) if args.encode else decrypt(inp.text, args.key)
        out.raw(result)
        if args.show_square:
            out.print()
            out.panel(format_square(square), title="key square")
        return 0

    # Auto-solve.
    inp = io.load(args)
    letters = clean_text(inp.text)
    if len(letters) < 30:
        out.warn(f"only {len(letters)} letters — Playfair wants ~100+ to break reliably")

    ranked = auto_solve(
        inp.text,
        wordlist_path=args.wordlist,
        restarts=max(1, args.restarts),
        iterations=max(1, args.iters),
        seed=args.seed,
        top=max(1, args.top),
        use_keyword=not args.sa_only,
        use_anneal=True if args.sa_only else None,
    )
    if not ranked:
        out.error("could not recover a key (try --restarts/--iters or a --wordlist)")
        return 1

    best = ranked[0]
    _, normalize = _make_scorer()
    n = len(_prepare(inp.text))
    quality = normalize(best.score, n)
    out.success(f"best key square: {best.key}  [{best.label}]  (score {best.score:.1f})")
    if quality <= _READABLE_THRESHOLD:
        out.warn("result does not look like English — the key may not be a dictionary "
                 "word; try more --restarts/--iters or a --wordlist")
    out.raw(best.plaintext)

    if args.show_square:
        out.print()
        out.panel(format_square(best.key), title="recovered key square")

    if len(ranked) > 1:
        out.print()
        out.table(
            ["rank", "score", "how", "key square", "plaintext"],
            [(i + 1, f"{s.score:8.1f}", s.label, s.key, _preview(s.plaintext))
             for i, s in enumerate(ranked)],
            title="candidate keys",
        )
    return 0


def _preview(text: str, width: int = 48) -> str:
    t = text.replace("\n", " ")
    return t if len(t) <= width else t[: width - 1] + "…"

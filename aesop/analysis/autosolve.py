"""
aesop.analysis.autosolve — the ``auto`` command, AESOP's one-shot solver.

The orchestrator that ties the whole workbench together.  Given an unknown blob
it runs a **staged pipeline**:

1. **Peel encodings.** Reuse :func:`aesop.encoding.magic.magic` to unwrap nested
   base64/hex/base32/gzip/… layers.  It is reliable and halts on a flag.
2. **Break ciphers.** For the original input and each promising decoded
   *terminal*, classify it (printable? Index of Coincidence?) and dispatch to the
   matching solver — Caesar/affine/rail-fence always (tiny key-spaces, can't
   overfit), and the expensive hill-climbers (substitution, Vigenère, columnar)
   only when the text is long enough to solve honestly, XOR for binary.
3. **Rank & report.** Score every candidate for genuine English-likeness, put
   flag matches first, and print the winning chain of steps.

This staged shape avoids the classic auto-solver failure mode — powerful solvers
overfitting short or non-text input and out-scoring the true plaintext.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import (
    clean_text,
    printable_ratio,
    index_of_coincidence,
    default_scorer,
)
from ..core.detect import identify, _looks_english
from ..encoding.magic import OPERATIONS as _MAGIC_OPS, DEFAULT_FLAG_RE

# Expensive hill-climbers overfit short text, so only run them on enough letters.
_MIN_LETTERS_EXPENSIVE = 40
_MIN_LETTERS_CIPHER = 3

# Pure encoding/compression decoders (the cipher-ish ops rot13/caesar/reverse are
# handled deliberately by the cipher stage, so we exclude them here).
_ENCODING_OPS = [(n, f) for n, f in _MAGIC_OPS if n not in ("rot13", "caesar", "reverse")]


@dataclass
class Node:
    steps: List[str]
    data: bytes
    is_flag: bool = False

    @property
    def text(self) -> str:
        return self.data.decode("latin-1")

    def key(self) -> bytes:
        return self.data


# --------------------------------------------------------------------------- #
# Ranking — prefer genuine English, not merely high quadgram score.
# --------------------------------------------------------------------------- #
def rank_score(data: bytes) -> float:
    """Higher = more likely to be the real answer."""
    pr = printable_ratio(data)
    if pr < 0.85:
        return -100.0  # unreadable → sink to the bottom
    text = data.decode("latin-1")
    alpha = clean_text(text)
    if len(alpha) < 2:
        return -50.0
    norm = default_scorer().score_normalized(text)   # ~ -2.5 English, ~ -7 gibberish
    bonus = 2.0 if _looks_english(text) else 0.0
    return norm + bonus


def _looks_solved(data: bytes, flag_pat: Optional["re.Pattern"]) -> bool:
    if flag_pat and flag_pat.search(data):
        return True
    return printable_ratio(data) > 0.9 and _looks_english(data.decode("latin-1"))


# --------------------------------------------------------------------------- #
# Cipher solving on a single (printable) terminal.
# --------------------------------------------------------------------------- #
def _looks_like_encoded_blob(text: str) -> bool:
    """Hex / base64-looking strings are not classical ciphertext — don't hill-climb them."""
    t = re.sub(r"\s", "", text)
    if len(t) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", t):
        return True
    if len(t) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", t) and any(c.isdigit() for c in t):
        # mixed-alphanumeric base64-ish (has digits) → treat as encoding, not cipher
        letters = sum(c.isalpha() for c in t)
        return letters / len(t) < 0.85
    return False


def cipher_candidates(data: bytes, spend: Callable[[], bool]) -> List[Tuple[str, bytes]]:
    """Run the appropriate cipher solvers on ``data``; return (step, output) list.

    ``spend()`` returns True while the expensive-solver budget lasts.
    """
    out: List[Tuple[str, bytes]] = []
    pr = printable_ratio(data)
    text = data.decode("latin-1")
    alpha = clean_text(text)

    is_encoded_blob = _looks_like_encoded_blob(text)
    already_english = pr > 0.9 and _looks_english(text)

    if pr > 0.6 and len(alpha) >= _MIN_LETTERS_CIPHER and not is_encoded_blob and not already_english:
        # Cheap, bounded-keyspace solvers — safe on any length.
        try:
            from ..classical.caesar import solve as caesar_solve
            best = caesar_solve(text, top=1)
            if best:
                out.append((f"caesar/shift-{best[0][0]}", best[0][1].encode("latin-1")))
        except Exception:
            pass
        try:
            from ..classical.affine import solve as affine_solve
            best = affine_solve(text, top=1)
            if best:
                out.append(("affine", best[0][1].encode("latin-1")))
        except Exception:
            pass
        try:
            from ..classical.transposition import solve_railfence
            best = solve_railfence(text, top=1)
            if best:
                out.append((f"railfence/{best[0][0]}", best[0][1].encode("latin-1")))
        except Exception:
            pass

        # Expensive hill-climbers — only on long enough text, and within budget.
        # The IC bands OVERLAP: a monoalphabetic cipher's IC dips below the 0.066
        # ideal on shorter text, so the ambiguous middle tries both families
        # rather than betting on a hard boundary.
        if len(alpha) >= _MIN_LETTERS_EXPENSIVE:
            ic = index_of_coincidence(text)
            if ic >= 0.052:   # monoalphabetic-ish (substitution / transposition)
                if spend():
                    try:
                        from ..classical.substitution import solve as subst_solve
                        _, pt, _ = subst_solve(text, restarts=40, iterations=5000)
                        out.append(("substitution", pt.encode("latin-1")))
                    except Exception:
                        pass
                if spend():
                    try:
                        from ..classical.transposition import solve_columnar
                        best = solve_columnar(text, top=1)
                        if best:
                            out.append((f"columnar/{best[0][0]}", best[0][2].encode("latin-1")))
                    except Exception:
                        pass
            if 0.035 <= ic <= 0.062:   # polyalphabetic-ish (Vigenère)
                if spend():
                    try:
                        from ..classical.vigenere import solve as vig_solve
                        key, pt, _ = vig_solve(text)
                        out.append((f"vigenere/{key}", pt.encode("latin-1")))
                    except Exception:
                        pass

    # XOR is attempted independently: single-byte XOR of ASCII text is often
    # *mostly printable*, so it must not be gated behind a "binary" check.
    # Skip only clean plaintext and pure encoded blobs.
    if len(data) >= 2 and not already_english and not is_encoded_blob:
        try:
            from ..classical.xor import solve as xor_solve
            key, pt = xor_solve(data)
            if key:
                out.append((f"xor/{key.hex()}", pt))
        except Exception:
            pass

    return out


def peel_encodings(
    data: bytes, depth: int, flag_pat: Optional["re.Pattern"], max_nodes: int = 80,
) -> List[Tuple[List[str], bytes]]:
    """Enumerate every reachable pure-encoding decode of ``data`` (breadth-first).

    Returns ``[(recipe, bytes), …]`` including the root (empty recipe).  If a flag
    is found, returns just that node so the caller can short-circuit.
    """
    seen = {data}
    nodes: List[Tuple[List[str], bytes]] = [([], data)]
    queue: List[Tuple[List[str], bytes]] = [([], data)]
    while queue and len(nodes) < max_nodes:
        recipe, d = queue.pop(0)
        if len(recipe) >= depth:
            continue
        for name, fn in _ENCODING_OPS:
            try:
                out_bytes = fn(d)
            except Exception:
                continue
            if not out_bytes or out_bytes in seen:
                continue
            seen.add(out_bytes)
            entry = (recipe + [name], out_bytes)
            if flag_pat and flag_pat.search(out_bytes):
                return [entry]
            nodes.append(entry)
            queue.append(entry)
    return nodes


def auto_solve(
    data: bytes,
    *,
    flag_re: Optional[str] = DEFAULT_FLAG_RE,
    depth: int = 8,
    expensive_budget: int = 6,
    max_terminals: int = 24,
    logger: Optional[Callable[[str], None]] = None,
) -> List[Node]:
    """Solve ``data``; return candidate solutions, best first."""
    flag_pat = re.compile(flag_re.encode("latin-1")) if flag_re else None
    log = logger or (lambda m: None)

    if flag_pat and flag_pat.search(data):
        return [Node([], data, is_flag=True)]
    if not flag_pat and _looks_solved(data, flag_pat):
        return [Node([], data)]

    # -- Stage 1: peel encoding layers (encoding ops only) ----------------- #
    peeled = peel_encodings(data, depth, flag_pat)
    if len(peeled) == 1 and flag_pat and flag_pat.search(peeled[0][1]):
        return [Node(peeled[0][0], peeled[0][1], is_flag=True)]

    # Every decoded layer is a terminal we may cipher-solve.
    terminals: List[Tuple[List[str], bytes]] = peeled[:max_terminals]

    # -- Stage 2: cipher-solve each terminal ------------------------------- #
    results: List[Node] = []
    seen_out = set()
    spent = [0]

    def spend() -> bool:
        if spent[0] >= expensive_budget:
            return False
        spent[0] += 1
        return True

    def record(steps: List[str], out_bytes: bytes) -> Optional[Node]:
        if out_bytes in seen_out:
            return None
        seen_out.add(out_bytes)
        node = Node(steps, out_bytes, is_flag=bool(flag_pat and flag_pat.search(out_bytes)))
        results.append(node)
        return node

    for recipe, tdata in terminals:
        n = record(recipe, tdata)
        if n and n.is_flag:
            return [n]
        parent_score = rank_score(tdata)
        for step, out_bytes in cipher_candidates(tdata, spend):
            is_flag = bool(flag_pat and flag_pat.search(out_bytes))
            # Keep a cipher result only if it actually reads as *more* English
            # than its parent (or is a flag). Stops solvers from replacing an
            # already-correct plaintext with a noisy near-duplicate.
            if not is_flag and rank_score(out_bytes) <= parent_score + 0.5:
                continue
            n = record(recipe + [step], out_bytes)
            if n and n.is_flag:
                return [n]

    if flag_pat and not any(n.is_flag for n in results):
        log("no flag found — showing the most readable candidates instead")

    results.sort(key=lambda n: (n.is_flag, rank_score(n.data)), reverse=True)
    return results


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "auto",
    group="analysis",
    summary="Identify, decode and break automatically — the one-command solver",
    manual="auto",
    aliases=["solve"],
    args=io_args(positional="data", positional_help="the mystery to solve") + [
        arg("--flag-format", "regex that marks the answer (stops the search)",
            dest="flag_format", default=DEFAULT_FLAG_RE),
        arg("--no-flag", "don't stop on a flag; rank by readability",
            dest="no_flag", action="store_true"),
        arg("--depth", "maximum encoding layers to peel", type=int, default=8),
        arg("--top", "how many candidate solutions to show", type=int, default=5),
        arg("--budget", "how many expensive hill-climb solves to allow", type=int, default=6),
    ],
    examples=[
        "aesop auto 'Uryyb, jbeyq!'",
        "aesop auto 'NBSWY3DPEB3W64TMMQ======'",
        "aesop auto -f challenge.txt --flag-format 'CTF\\{.*\\}'",
    ],
    description="""
        The flagship solver.  First peels nested encodings, then — when the data
        looks like a cipher — dispatches to the matching breaker (Caesar, affine,
        substitution, Vigenère, transposition, XOR), guided by the Index of
        Coincidence so an expensive hill-climb only runs when it is warranted.
        It halts on readable text or a flag and prints the chain of steps.
    """,
)
def cmd_auto(args, out) -> int:
    inp = io.load(args, binary=True)
    flag_re = None if args.no_flag else args.flag_format

    guesses = identify(inp.data)
    if guesses:
        g = guesses[0]
        out.hint(f"triage: likely {g.label} ({g.confidence:.0%}) — {g.reason}")

    results = auto_solve(
        inp.data, flag_re=flag_re, depth=max(1, args.depth),
        expensive_budget=max(0, args.budget), logger=out.hint,
    )
    if not results:
        out.warn("could not make progress automatically")
        out.hint("try `aesop identify` then a specific solver, or `aesop manual auto`")
        return 1

    best = results[0]
    chain = " → ".join(best.steps) if best.steps else "(input needed no transform)"
    if best.is_flag:
        out.success(f"solved! flag via: {chain}")
    elif best.steps:
        out.success(f"best solution via: {chain}")
    else:
        out.info("input already looks like the answer")
    out.raw(io.as_display(best.data))

    extra = [r for r in results[1:] if r.steps and printable_ratio(r.data) > 0.6][: max(0, args.top - 1)]
    if extra:
        out.print()
        rows = [(" → ".join(r.steps), f"{rank_score(r.data):6.2f}", _snippet(r.data)) for r in extra]
        out.table(["steps", "score", "preview"], rows, title="other candidates")
    return 0


def _snippet(data: bytes, width: int = 48) -> str:
    s = data.decode("latin-1") if printable_ratio(data) > 0.85 else data.hex()
    s = s.replace("\n", " ")
    return s if len(s) <= width else s[: width - 1] + "…"

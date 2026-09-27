"""
aesop.encoding.magic — the auto-decoder.

Point it at a blob that has been wrapped in "some layers of stuff" and it peels
them.  It performs a best-first search over a library of reversible decodings
(base64/32/85, hex, binary, url, gzip/zlib, ROT13, reverse, …), at each step
asking "does this look like a flag or readable text yet?".  The winning path is
reported as a *recipe* so the result is reproducible.

This is AESOP's answer to CyberChef's "Magic" — but driven from the terminal and
tuned to stop the moment a flag appears.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import printable_ratio, shannon_entropy, clean_text, score_text

DEFAULT_FLAG_RE = r"[A-Za-z0-9_]{2,}\{[^}\n]{1,200}\}"


# --------------------------------------------------------------------------- #
# Reversible decoding operations: each maps bytes -> bytes or raises.
# --------------------------------------------------------------------------- #
def _from_hex(d: bytes) -> bytes:
    s = re.sub(rb"\s", b"", d)
    if not s or len(s) % 2 or not re.fullmatch(rb"[0-9a-fA-F]+", s):
        raise ValueError("not hex")
    return binascii.unhexlify(s)


def _from_base64(d: bytes) -> bytes:
    s = re.sub(rb"\s", b"", d)
    if len(s) < 4 or not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", s):
        raise ValueError("not base64")
    out = base64.b64decode(s + b"=" * (-len(s) % 4))
    if not out:
        raise ValueError("empty")
    return out


def _from_base64url(d: bytes) -> bytes:
    s = re.sub(rb"\s", b"", d)
    if len(s) < 4 or not re.fullmatch(rb"[A-Za-z0-9_\-]+={0,2}", s) or (b"-" not in s and b"_" not in s):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _from_base32(d: bytes) -> bytes:
    s = re.sub(rb"\s", b"", d).upper()
    if len(s) < 8 or len(s) % 8 or not re.fullmatch(rb"[A-Z2-7]+={0,6}", s):
        raise ValueError("not base32")
    return base64.b32decode(s)


def _from_base85(d: bytes) -> bytes:
    s = re.sub(rb"\s", b"", d)
    if len(s) < 4:
        raise ValueError("too short")
    return base64.b85decode(s)


def _from_binary(d: bytes) -> bytes:
    s = re.sub(rb"\s", b"", d)
    if not s or len(s) % 8 or not re.fullmatch(rb"[01]+", s):
        raise ValueError("not binary")
    return bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))


def _from_decimal(d: bytes) -> bytes:
    parts = d.split()
    if len(parts) < 2 or not all(p.isdigit() and int(p) < 256 for p in parts):
        raise ValueError("not decimal bytes")
    return bytes(int(p) for p in parts)


def _url_decode(d: bytes) -> bytes:
    if b"%" not in d:
        raise ValueError("no percent-encoding")
    return urllib.parse.unquote_to_bytes(d.decode("latin-1"))


def _gunzip(d: bytes) -> bytes:
    if d[:2] != b"\x1f\x8b":
        raise ValueError("not gzip")
    return gzip.decompress(d)


def _zlib_inflate(d: bytes) -> bytes:
    if not d or d[0] != 0x78:
        raise ValueError("not zlib")
    return zlib.decompress(d)


def _rot13(d: bytes) -> bytes:
    try:
        return codecs.encode(d.decode("ascii"), "rot13").encode("ascii")
    except Exception:
        raise ValueError("not rot13-able")


def _reverse(d: bytes) -> bytes:
    return d[::-1]


def _best_caesar(d: bytes) -> bytes:
    """Try all 26 shifts on the letters, keep the most English-like."""
    try:
        text = d.decode("ascii")
    except Exception:
        raise ValueError("not ascii")
    if len(clean_text(text)) < 8:
        raise ValueError("too little text")

    def sh(t, n):
        out = []
        for ch in t:
            if "a" <= ch <= "z":
                out.append(chr((ord(ch) - 97 + n) % 26 + 97))
            elif "A" <= ch <= "Z":
                out.append(chr((ord(ch) - 65 + n) % 26 + 65))
            else:
                out.append(ch)
        return "".join(out)

    best = max(range(1, 26), key=lambda n: score_text(sh(text, n)))
    return sh(text, best).encode("latin-1")


OPERATIONS: List[Tuple[str, Callable[[bytes], bytes]]] = [
    ("from-base64", _from_base64),
    ("from-base64url", _from_base64url),
    ("from-hex", _from_hex),
    ("from-base32", _from_base32),
    ("from-base85", _from_base85),
    ("from-binary", _from_binary),
    ("from-decimal", _from_decimal),
    ("url-decode", _url_decode),
    ("gunzip", _gunzip),
    ("zlib-inflate", _zlib_inflate),
    ("rot13", _rot13),
    ("caesar", _best_caesar),
    ("reverse", _reverse),
]


@dataclass
class MagicResult:
    recipe: List[str]
    data: bytes
    score: float
    is_flag: bool = False

    @property
    def text(self) -> str:
        return self.data.decode("latin-1")


def _readability(data: bytes) -> float:
    """Higher = more likely to be the answer."""
    if not data:
        return -1e9
    pr = printable_ratio(data)
    if pr < 0.6:
        # Reward low-entropy structure even if not printable (further decodable).
        return -shannon_entropy(data) - (1 - pr) * 5
    eng = score_text(data.decode("latin-1")) / max(1, len(clean_text(data.decode("latin-1"))))
    return pr * 3 + eng


def magic(
    data: bytes,
    *,
    depth: int = 6,
    flag_re: Optional[str] = DEFAULT_FLAG_RE,
    max_nodes: int = 4000,
) -> List[MagicResult]:
    """Best-first search over decodings.  Returns candidates, best first.

    Stops early and prioritises any result matching ``flag_re``.
    """
    flag_pat = re.compile(flag_re.encode("latin-1")) if flag_re else None
    start = MagicResult(recipe=[], data=data, score=_readability(data))
    if flag_pat and flag_pat.search(data):
        start.is_flag = True
        return [start]

    seen = {data}
    # frontier as a simple list used as a priority queue (small N, fine).
    frontier: List[MagicResult] = [start]
    results: List[MagicResult] = []
    flags: List[MagicResult] = []
    nodes = 0

    while frontier and nodes < max_nodes:
        frontier.sort(key=lambda r: r.score, reverse=True)
        node = frontier.pop(0)
        if len(node.recipe) >= depth:
            continue
        for name, fn in OPERATIONS:
            try:
                out = fn(node.data)
            except Exception:
                continue
            if not out or out in seen:
                continue
            seen.add(out)
            nodes += 1
            child = MagicResult(recipe=node.recipe + [name], data=out, score=_readability(out))
            if flag_pat and flag_pat.search(out):
                child.is_flag = True
                flags.append(child)
                return sorted(flags, key=lambda r: (r.is_flag, -len(r.recipe)), reverse=True)
            results.append(child)
            frontier.append(child)

    results.sort(key=lambda r: r.score, reverse=True)
    return results


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@command(
    "magic",
    group="encoding",
    summary="Auto-detect and peel nested encodings (à la CyberChef Magic)",
    manual="magic",
    aliases=["auto-decode"],
    args=io_args(positional="data", positional_help="the wrapped blob to unpeel") + [
        arg("--depth", "maximum recipe length to search", type=int, default=6),
        arg("--flag-format", "regex that marks the answer (stops the search)",
            dest="flag_format", default=DEFAULT_FLAG_RE),
        arg("--no-flag", "don't stop on a flag pattern; rank by readability",
            dest="no_flag", action="store_true"),
        arg("--top", "how many candidate results to show", type=int, default=5),
    ],
    examples=[
        "aesop magic 'NBSWY3DPEB3W64TMMQ======'          # base32 -> text",
        "echo 'ZmxhZ3tuZXN0ZWR9' | aesop magic",
        "aesop magic --depth 8 --flag-format 'CTF\\{.*\\}' -f blob.txt",
    ],
    description="""
        Peels layered encodings automatically with a best-first search: at each
        step it tries every reversible decoding (base64/32/85, hex, binary, url,
        gzip/zlib, ROT13/Caesar, reverse) and follows the branches that look most
        like readable text — halting the instant a flag pattern appears.  The
        winning path is printed as a reproducible recipe.
    """,
)
def cmd_magic(args, out) -> int:
    inp = io.load(args, binary=True)
    flag_re = None if args.no_flag else args.flag_format
    results = magic(inp.data, depth=max(1, args.depth), flag_re=flag_re)
    if not results:
        out.warn("no decoding produced a better result")
        out.raw(io.as_display(inp.data))
        return 1

    best = results[0]
    if best.is_flag:
        out.success(f"flag found via: {' → '.join(best.recipe) or '(input already a flag)'}")
    else:
        out.success(f"best result via: {' → '.join(best.recipe) or '(no transform needed)'}")
    out.raw(io.as_display(best.data))

    extra = [r for r in results[1:] if r.recipe][: max(0, args.top - 1)]
    if extra:
        out.print()
        rows = [(" → ".join(r.recipe), f"{r.score:6.2f}", _snippet(r.data)) for r in extra]
        out.table(["recipe", "score", "preview"], rows, title="other candidates")
    return 0


def _snippet(data: bytes, width: int = 48) -> str:
    from ..core.score import printable_ratio
    s = data.decode("latin-1") if printable_ratio(data) > 0.85 else data.hex()
    s = s.replace("\n", " ")
    return s if len(s) <= width else s[: width - 1] + "…"

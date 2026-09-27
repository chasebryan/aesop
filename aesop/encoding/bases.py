"""
aesop.encoding.bases — the everyday base/format codecs.

The unglamorous but constantly-needed conversions: Base64 (standard and
URL-safe), Base32, Base58 (the Bitcoin alphabet, no external deps), Base85 /
ASCII85, hexadecimal, binary bit-strings and URL percent-encoding.  In *The Fox
and the Grapes* the fox cannot reach what looks delicious; here the "grapes" are
just data wrapped in a skin — and every skin peels off cleanly.

Like every AESOP module this keeps two halves apart:

1. A **programmatic API** — pure functions on ``bytes``/``str`` (``b64_encode``,
   ``b58_decode``, …).  No printing, fully importable and testable.
2. Thin **command handlers** wired in with :func:`aesop.registry.command`, which
   only marshal arguments, load input and present the result via ``out``.

Every command *encodes* by default and *decodes* with ``-d``.  The primary
result is always emitted with ``out.raw`` so the tool composes in a pipe:

    $ aesop b64 'Attack at dawn' | aesop b64 -d
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from typing import Optional

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import printable_ratio


# =========================================================================== #
# Programmatic API
# --------------------------------------------------------------------------- #
# Every ``*_encode`` takes ``bytes`` and returns an ASCII ``str``; every
# ``*_decode`` takes a ``str`` and returns ``bytes``.  Decoders are deliberately
# lenient: they strip whitespace and repair missing ``=`` padding so a value
# copied out of a log or a chat window still round-trips.
# =========================================================================== #

# ---- Base64 --------------------------------------------------------------- #
def b64_encode(data: bytes, url: bool = False) -> str:
    """Standard Base64, or URL-safe (``-``/``_``) when ``url`` is true."""
    enc = base64.urlsafe_b64encode if url else base64.b64encode
    return enc(data).decode("ascii")


def b64_decode(s: str, url: bool = False) -> bytes:
    """Decode Base64, accepting either alphabet and any (or no) padding.

    ``-``/``_`` are normalised to ``+``/``/`` so URL-safe and standard input
    both decode, regardless of ``url``; missing ``=`` padding is restored.
    """
    t = re.sub(r"\s", "", s).replace("-", "+").replace("_", "/")
    t = t.rstrip("=")
    t += "=" * (-len(t) % 4)
    return base64.b64decode(t)


# ---- Base32 --------------------------------------------------------------- #
def b32_encode(data: bytes) -> str:
    """RFC 4648 Base32 (upper-case, ``=`` padded)."""
    return base64.b32encode(data).decode("ascii")


def b32_decode(s: str) -> bytes:
    """Decode Base32, case-insensitively, repairing missing padding."""
    t = re.sub(r"\s", "", s).upper().rstrip("=")
    t += "=" * (-len(t) % 8)
    return base64.b32decode(t, casefold=True)


# ---- Base58 (Bitcoin alphabet, dependency-free) --------------------------- #
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}


def b58_encode(data: bytes) -> str:
    """Base58 in the Bitcoin alphabet (no 0/O/I/l), leading zeros -> ``1``.

    Each leading ``0x00`` byte becomes a leading ``'1'`` character, exactly as
    Base58Check addresses require.
    """
    n = int.from_bytes(data, "big")
    chars = []
    while n > 0:
        n, r = divmod(n, 58)
        chars.append(B58_ALPHABET[r])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(chars))


def b58_decode(s: str) -> bytes:
    """Decode Base58 (Bitcoin alphabet), restoring leading zero bytes."""
    t = re.sub(r"\s", "", s)
    n = 0
    for ch in t:
        if ch not in _B58_INDEX:
            raise ValueError(f"invalid base58 character: {ch!r}")
        n = n * 58 + _B58_INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in t:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


# ---- Base85 / ASCII85 ----------------------------------------------------- #
def b85_encode(data: bytes, ascii85: bool = False) -> str:
    """RFC-1924 Base85 by default, or Adobe ASCII85 when ``ascii85`` is true."""
    enc = base64.a85encode if ascii85 else base64.b85encode
    return enc(data).decode("ascii")


def b85_decode(s: str, ascii85: bool = False) -> bytes:
    """Decode Base85 (RFC 1924) or, with ``ascii85``, Adobe ASCII85."""
    t = s.strip()
    if ascii85:
        return base64.a85decode(t)
    return base64.b85decode(re.sub(r"\s", "", t))


# ---- Hexadecimal ---------------------------------------------------------- #
def hex_encode(data: bytes) -> str:
    """Lower-case hex, two characters per byte, no separators."""
    return data.hex()


def hex_decode(s: str) -> bytes:
    """Decode hex, tolerating whitespace, ``:``/``-`` separators and ``0x``."""
    t = re.sub(r"\s", "", s)
    t = re.sub(r"(?i)0x", "", t)
    t = t.replace(":", "").replace("-", "").replace(",", "")
    if len(t) % 2:
        raise ValueError("hex string has an odd number of digits")
    return bytes.fromhex(t)


# ---- Binary bit-strings --------------------------------------------------- #
def binary_encode(data: bytes, packed: bool = False) -> str:
    """Render each byte as 8 bits; space-separated per byte unless ``packed``."""
    bits = [format(b, "08b") for b in data]
    return "".join(bits) if packed else " ".join(bits)


def binary_decode(s: str) -> bytes:
    """Decode a ``0``/``1`` string (spaced or not) back to bytes.

    Any character that is not ``0`` or ``1`` is ignored, so spaced, packed and
    comma-separated bit-strings all decode.  A run shorter than a byte is
    left-padded with zeros.
    """
    t = re.sub(r"[^01]", "", s)
    if not t:
        return b""
    t = "0" * (-len(t) % 8) + t
    return bytes(int(t[i : i + 8], 2) for i in range(0, len(t), 8))


# ---- URL percent-encoding ------------------------------------------------- #
def url_encode(data: bytes) -> str:
    """Percent-encode every byte except the RFC 3986 unreserved set."""
    return urllib.parse.quote(data, safe="")


def url_decode(s: str) -> bytes:
    """Reverse percent-encoding, returning raw bytes."""
    return urllib.parse.unquote_to_bytes(s.strip())


# =========================================================================== #
# Presentation helper
# --------------------------------------------------------------------------- #
def _emit_bytes(data: bytes) -> str:
    """Decoded bytes for ``out.raw``: text when printable, else hex."""
    if printable_ratio(data) > 0.9:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")
    return data.hex()


# =========================================================================== #
# CLI handlers
# --------------------------------------------------------------------------- #
# Encode paths take plaintext, so they load raw (io.load(args, encoding="raw"))
# and never let the hex/base64 sniffer touch the bytes.  Decode paths also load
# raw: the command already names the encoding, so we want the exact string the
# user supplied and decode it ourselves — letting the autodetector pre-decode a
# base64/hex literal here would be wrong.
# --------------------------------------------------------------------------- #
@command(
    "b64",
    group="encoding",
    summary="Encode to (or decode from) Base64, standard or URL-safe",
    manual="bases",
    aliases=["base64"],
    args=io_args(positional="data", positional_help="data to encode (or Base64 to decode with -d)") + [
        arg("-d --decode", "decode Base64 back to bytes (default is encode)", action="store_true"),
        arg("--url", "use the URL-safe alphabet (- and _ for + and /)", action="store_true"),
    ],
    examples=[
        "aesop b64 'Hello, AESOP!'                 # -> SGVsbG8sIEFFU09QIQ==",
        "aesop b64 -d 'SGVsbG8sIEFFU09QIQ=='       # -> Hello, AESOP!",
        "aesop b64 --url -f photo.png              # URL-safe, from a file",
        "echo 'Attack at dawn' | aesop b64 | aesop b64 -d",
    ],
    description="""
        Base64 packs three bytes into four printable characters — the workhorse
        for stuffing binary into text.  --url selects the URL/filename-safe
        alphabet (- and _ instead of + and /).  Decoding is lenient: whitespace
        is stripped, either alphabet is accepted, and missing '=' padding is
        restored automatically.
    """,
)
def cmd_b64(args, out) -> int:
    if args.decode:
        inp = io.load(args, encoding="raw")
        out.raw(_emit_bytes(b64_decode(inp.text, url=args.url)))
    else:
        inp = io.load(args, encoding="raw")
        out.raw(b64_encode(inp.data, url=args.url))
    return 0


@command(
    "b32",
    group="encoding",
    summary="Encode to (or decode from) Base32 (RFC 4648)",
    manual="bases",
    aliases=["base32"],
    args=io_args(positional="data", positional_help="data to encode (or Base32 to decode with -d)") + [
        arg("-d --decode", "decode Base32 back to bytes (default is encode)", action="store_true"),
    ],
    examples=[
        "aesop b32 'Hello, AESOP!'                 # -> JBSWY3DPFQQEK5DQPFISA===",
        "aesop b32 -d 'NBSWY3DP'                   # -> hello",
        "echo 'Attack at dawn' | aesop b32 | aesop b32 -d",
    ],
    description="""
        Base32 encodes five bytes into eight characters using A-Z and 2-7 — a
        larger but case-insensitive and typo-resistant alphabet, common in TOTP
        secrets and onion addresses.  Decoding folds case, strips whitespace and
        repairs missing '=' padding.
    """,
)
def cmd_b32(args, out) -> int:
    if args.decode:
        inp = io.load(args, encoding="raw")
        out.raw(_emit_bytes(b32_decode(inp.text)))
    else:
        inp = io.load(args, encoding="raw")
        out.raw(b32_encode(inp.data))
    return 0


@command(
    "b58",
    group="encoding",
    summary="Encode to (or decode from) Base58 (Bitcoin alphabet)",
    manual="bases",
    aliases=["base58"],
    args=io_args(positional="data", positional_help="data to encode (or Base58 to decode with -d)") + [
        arg("-d --decode", "decode Base58 back to bytes (default is encode)", action="store_true"),
    ],
    examples=[
        "aesop b58 'Hello, AESOP!'                 # -> compact, no 0/O/I/l",
        "aesop b58 -d '2NEpo7TZRhna7vSvL'          # -> Hello World",
        "echo 'Attack at dawn' | aesop b58 | aesop b58 -d",
    ],
    description="""
        Base58 is Base62 minus the visually ambiguous characters (0, O, I, l),
        the encoding behind Bitcoin addresses and IPFS CIDs.  It is a pure
        big-integer conversion — implemented here with no external dependency —
        and each leading zero byte is preserved as a leading '1'.
    """,
)
def cmd_b58(args, out) -> int:
    if args.decode:
        inp = io.load(args, encoding="raw")
        out.raw(_emit_bytes(b58_decode(inp.text)))
    else:
        inp = io.load(args, encoding="raw")
        out.raw(b58_encode(inp.data))
    return 0


@command(
    "b85",
    group="encoding",
    summary="Encode to (or decode from) Base85 (RFC 1924) or ASCII85",
    manual="bases",
    aliases=["base85", "ascii85"],
    args=io_args(positional="data", positional_help="data to encode (or Base85 to decode with -d)") + [
        arg("-d --decode", "decode Base85 back to bytes (default is encode)", action="store_true"),
        arg("-a --ascii85", "use Adobe ASCII85 instead of RFC-1924 Base85", action="store_true"),
    ],
    examples=[
        "aesop b85 'Hello, AESOP!'                 # -> RFC-1924 Base85",
        "aesop b85 -d 'NM&qnZ!91|MN>~uAp'         # -> Hello, AESOP!",
        "aesop b85 --ascii85 'Hello, AESOP!'       # Adobe ASCII85 variant",
        "echo 'Attack at dawn' | aesop b85 | aesop b85 -d",
    ],
    description="""
        Base85 packs four bytes into five characters — denser than Base64.  The
        default is the RFC-1924 alphabet (also used by Git and Python's
        base64.b85); --ascii85 selects the Adobe/PostScript ASCII85 variant.
        Encoding is raw bytes-in; decoding strips whitespace.
    """,
)
def cmd_b85(args, out) -> int:
    if args.decode:
        inp = io.load(args, encoding="raw")
        out.raw(_emit_bytes(b85_decode(inp.text, ascii85=args.ascii85)))
    else:
        inp = io.load(args, encoding="raw")
        out.raw(b85_encode(inp.data, ascii85=args.ascii85))
    return 0


@command(
    "hex",
    group="encoding",
    summary="Encode bytes to hex (or decode hex back to bytes)",
    manual="bases",
    aliases=["tohex"],
    args=io_args(positional="data", positional_help="data to hex-encode (or hex to decode with -d)") + [
        arg("-d --decode", "decode hex back to bytes (default is encode)", action="store_true"),
    ],
    examples=[
        "aesop hex 'Hello, AESOP!'                 # -> 48656c6c6f2c204145534f5021",
        "aesop hex -d '48656c6c6f'                 # -> Hello",
        "aesop hex -d 'de:ad:be:ef'                # separators tolerated",
        "echo 'Attack at dawn' | aesop hex | aesop hex -d",
    ],
    description="""
        Plain hexadecimal: two lower-case characters per byte with no
        separators on encode.  Decoding is forgiving — whitespace, ':'/'-'/','
        separators and a leading '0x' are stripped before conversion, so hex
        dumped from almost any tool round-trips.
    """,
)
def cmd_hex(args, out) -> int:
    if args.decode:
        inp = io.load(args, encoding="raw")
        out.raw(_emit_bytes(hex_decode(inp.text)))
    else:
        inp = io.load(args, encoding="raw")
        out.raw(hex_encode(inp.data))
    return 0


@command(
    "binary",
    group="encoding",
    summary="Convert bytes to a 0/1 bit-string (or back with -d)",
    manual="bases",
    aliases=["bits"],
    args=io_args(positional="data", positional_help="data to encode (or a bit-string to decode with -d)") + [
        arg("-d --decode", "decode a 0/1 bit-string back to bytes (default is encode)", action="store_true"),
        arg("--packed", "emit bits with no spaces between bytes", action="store_true"),
    ],
    examples=[
        "aesop binary 'Hi'                         # -> 01001000 01101001",
        "aesop binary --packed 'Hi'                # -> 0100100001101001",
        "aesop binary -d '01001000 01101001'       # -> Hi",
        "echo 'Attack at dawn' | aesop binary | aesop binary -d",
    ],
    description="""
        Renders each byte as eight bits.  By default bytes are separated by a
        space for readability; --packed removes the spaces.  Decoding ignores
        every character that is not 0 or 1, so spaced, packed and
        comma-separated bit-strings all decode, and a short run is left-padded to
        a whole byte.
    """,
)
def cmd_binary(args, out) -> int:
    if args.decode:
        inp = io.load(args, encoding="raw")
        out.raw(_emit_bytes(binary_decode(inp.text)))
    else:
        inp = io.load(args, encoding="raw")
        out.raw(binary_encode(inp.data, packed=args.packed))
    return 0


@command(
    "url",
    group="encoding",
    summary="URL percent-encode data (or decode it with -d)",
    manual="bases",
    aliases=["percent"],
    args=io_args(positional="data", positional_help="data to encode (or percent-encoded text to decode with -d)") + [
        arg("-d --decode", "decode percent-encoding back to bytes (default is encode)", action="store_true"),
    ],
    examples=[
        "aesop url 'a b&c=d'                        # -> a%20b%26c%3Dd",
        "aesop url -d 'a%20b%26c%3Dd'               # -> a b&c=d",
        "echo 'Attack at dawn' | aesop url | aesop url -d",
    ],
    description="""
        RFC 3986 percent-encoding: every byte outside the unreserved set
        (A-Z a-z 0-9 and - _ . ~) becomes %XX.  Encoding treats input as raw
        bytes, so it is safe for binary; decoding reverses any %XX escape and
        returns the original bytes.
    """,
)
def cmd_url(args, out) -> int:
    if args.decode:
        inp = io.load(args, encoding="raw")
        out.raw(_emit_bytes(url_decode(inp.text)))
    else:
        inp = io.load(args, encoding="raw")
        out.raw(url_encode(inp.data))
    return 0

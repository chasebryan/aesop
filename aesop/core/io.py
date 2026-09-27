"""
aesop.core.io — smart input handling.

One of the reasons other tools are painful is that you constantly have to tell
them *how* your data is encoded.  AESOP guesses.  Give it a hex string, a
base64 blob, a file path, or raw text, and :func:`read_input` returns bytes,
telling you what it inferred so you can override if it guessed wrong.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import sys
from dataclasses import dataclass
from typing import Optional

_HEX_RE = re.compile(r"^[0-9a-fA-F\s]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9\-_=\s]+$")


@dataclass
class LoadedInput:
    """Result of :func:`read_input`: the bytes plus how we obtained them."""

    data: bytes
    source: str          # "file:<path>" | "stdin" | "literal"
    encoding: str        # "raw" | "hex" | "base64" | "base64url" | "bytes"

    @property
    def text(self) -> str:
        return self.data.decode("latin-1")

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.data)


def _looks_like_hex(s: str) -> bool:
    t = re.sub(r"\s", "", s)
    return len(t) >= 2 and len(t) % 2 == 0 and bool(_HEX_RE.match(s))


def _looks_like_b64(s: str) -> bool:
    t = re.sub(r"\s", "", s)
    if len(t) < 8 or len(t) % 4 != 0:
        return False
    if not _B64_RE.match(s):
        return False
    try:
        base64.b64decode(t, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def decode_encoded(s: str, encoding: str) -> bytes:
    """Decode ``s`` using an explicit encoding name."""
    t = re.sub(r"\s", "", s)
    if encoding == "raw":
        return s.encode("utf-8")
    if encoding == "hex":
        return bytes.fromhex(t)
    if encoding == "base64":
        return base64.b64decode(t + "=" * (-len(t) % 4))
    if encoding == "base64url":
        return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
    raise ValueError(f"unknown encoding: {encoding}")


def sniff_encoding(s: str) -> str:
    """Best-effort guess of how a string is encoded.

    Deliberately conservative: a string of only letters (and spaces) is treated
    as **raw**, because that is the overwhelming case in classical cryptanalysis
    (Caesar/Vigenère/substitution ciphertext looks exactly like that, and much
    of it is coincidentally valid base64/hex).  We only auto-pick hex or base64
    when the string carries a tell — a digit or a base64-only symbol — or is far
    too long to be plausible prose.  Users can always force with ``-e``.
    """
    t = re.sub(r"\s", "", s)
    if not t:
        return "raw"
    has_digit = any(c.isdigit() for c in t)
    has_b64_special = any(c in "+/=" for c in t)
    has_url_special = ("-" in t) or ("_" in t)

    # Hex: even length, all hex chars, and a digit present (or improbably long).
    if len(t) % 2 == 0 and _looks_like_hex(s) and (has_digit or len(t) >= 32):
        return "hex"
    # Base64url: needs a URL-only symbol to disambiguate from standard base64.
    if len(t) % 4 == 0 and _B64URL_RE.match(s) and has_url_special:
        return "base64url"
    # Base64: valid, and carries a non-letter so we don't swallow alpha text.
    if _looks_like_b64(s) and (has_digit or has_b64_special):
        return "base64"
    return "raw"


def read_input(
    value: Optional[str],
    *,
    encoding: str = "auto",
    from_file: Optional[str] = None,
    use_stdin: bool = False,
    binary: bool = False,
) -> LoadedInput:
    """Resolve user input into bytes.

    Priority: ``from_file`` > explicit ``value`` > stdin (when ``use_stdin`` or
    ``value`` is ``None`` and stdin is not a tty).

    ``encoding='auto'`` sniffs hex/base64/raw.  Pass an explicit encoding to
    force it.
    """
    # 1. File
    if from_file:
        with open(from_file, "rb") as fh:
            raw = fh.read()
        if binary:
            return LoadedInput(raw, f"file:{from_file}", "bytes")
        text = raw.decode("latin-1")
        enc = encoding if encoding != "auto" else sniff_encoding(text.strip())
        if enc == "raw":
            return LoadedInput(raw, f"file:{from_file}", "bytes")
        try:
            return LoadedInput(decode_encoded(text.strip(), enc), f"file:{from_file}", enc)
        except Exception:
            return LoadedInput(raw, f"file:{from_file}", "bytes")

    # 2. Literal value
    if value is not None:
        enc = encoding if encoding != "auto" else sniff_encoding(value.strip())
        data = decode_encoded(value.strip() if enc != "raw" else value, enc)
        return LoadedInput(data, "literal", enc)

    # 3. stdin
    if use_stdin or not sys.stdin.isatty():
        raw = sys.stdin.buffer.read()
        if binary:
            return LoadedInput(raw, "stdin", "bytes")
        text = raw.decode("latin-1")
        enc = encoding if encoding != "auto" else sniff_encoding(text.strip())
        if enc == "raw":
            return LoadedInput(text.encode("utf-8"), "stdin", "raw")
        try:
            return LoadedInput(decode_encoded(text.strip(), enc), "stdin", enc)
        except Exception:
            return LoadedInput(raw, "stdin", "bytes")

    raise ValueError("no input provided (give a value, --file, or pipe via stdin)")


def load(args, *, value_attr: str = "text", file_attr: str = "file",
         encoding_attr: str = "in_encoding", binary: bool = False,
         encoding: Optional[str] = None) -> LoadedInput:
    """Resolve input from a parsed argparse ``Namespace``.

    Pairs with :func:`aesop.registry.io_args`.  Commands call
    ``inp = io.load(args)`` and then use ``inp.data`` / ``inp.text``.

    Pass an explicit ``encoding`` to override the user/auto choice — encoders
    should pass ``encoding='raw'`` so that plaintext which happens to be valid
    base64/hex (e.g. "Attack at dawn") is not silently decoded.
    """
    value = getattr(args, value_attr, None)
    from_file = getattr(args, file_attr, None)
    if encoding is None:
        encoding = getattr(args, encoding_attr, "auto") or "auto"
    return read_input(value, encoding=encoding, from_file=from_file, binary=binary)


def as_display(data: bytes, max_len: int = 2048) -> str:
    """Render bytes for terminal display: printable as-is, else hex."""
    from .score import printable_ratio

    truncated = data[:max_len]
    if printable_ratio(truncated) > 0.9:
        out = truncated.decode("latin-1")
    else:
        out = truncated.hex()
    if len(data) > max_len:
        out += f"\n… ({len(data) - max_len} more bytes)"
    return out

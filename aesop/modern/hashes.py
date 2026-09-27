"""
aesop.modern.hashes — hash identification, digests, dictionary cracking and
Merkle–Damgård length-extension.

Like the fox studying a footprint to name the beast that made it, this module
reads a hash by its *shape* before it ever tries to break it.  It has four
capabilities, each wired to its own CLI command but all sharing one manual page
(``aesop manual hashes``):

* ``hash-id`` — name the likely algorithm(s) from length + charset + prefix.
* ``hash``    — compute digests (md5/sha1/sha256/…/ntlm/crc32) of any input.
* ``crack``   — dictionary attack with mutations against an unsalted digest.
* ``length-extension`` — forge ``H(secret ‖ data ‖ pad ‖ append)`` from a known
  ``H(secret ‖ data)`` and the secret's *length* alone (md5 & sha1).

As with every AESOP module the file has two clean halves: a pure, importable
**programmatic API** (functions on ``str``/``bytes``, no printing) and thin
**CLI handlers** that only marshal args, call :func:`aesop.core.io.load`, and
present results through the shared :class:`aesop.ui.Output`.

The length-extension attack needs to *resume* a hash from a known digest, which
``hashlib`` cannot do — so this module carries compact, self-contained
pure-Python MD5 and SHA-1 (and an MD4 for NTLM, since modern OpenSSL builds drop
it).  They are used only where hashlib cannot serve; ``hash`` still prefers
hashlib for everything it offers.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import struct
import zlib
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from ..registry import command, arg, io_args
from ..core import io

DEFAULT_WORDLIST = "/usr/share/dict/words"

# --------------------------------------------------------------------------- #
# Pure-Python MD4 (for NTLM — OpenSSL drops md4 in FIPS/3.x default providers)
# --------------------------------------------------------------------------- #
def _lrot(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(data: bytes) -> bytes:
    """Compute the 16-byte MD4 digest of ``data`` (RFC 1320), pure Python."""
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    msg = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        AA, BB, CC, DD = A, B, C, D
        # Round 1
        for i in range(4):
            k = i * 4
            A = _lrot(A + F(B, C, D) + X[k], 3)
            D = _lrot(D + F(A, B, C) + X[k + 1], 7)
            C = _lrot(C + F(D, A, B) + X[k + 2], 11)
            B = _lrot(B + F(C, D, A) + X[k + 3], 19)
        # Round 2
        for i in range(4):
            A = _lrot(A + G(B, C, D) + X[i] + 0x5A827999, 3)
            D = _lrot(D + G(A, B, C) + X[i + 4] + 0x5A827999, 5)
            C = _lrot(C + G(D, A, B) + X[i + 8] + 0x5A827999, 9)
            B = _lrot(B + G(C, D, A) + X[i + 12] + 0x5A827999, 13)
        # Round 3
        for i in (0, 2, 1, 3):
            A = _lrot(A + H(B, C, D) + X[i] + 0x6ED9EBA1, 3)
            D = _lrot(D + H(A, B, C) + X[i + 8] + 0x6ED9EBA1, 9)
            C = _lrot(C + H(D, A, B) + X[i + 4] + 0x6ED9EBA1, 11)
            B = _lrot(B + H(C, D, A) + X[i + 12] + 0x6ED9EBA1, 15)
        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF
    return struct.pack("<4I", A, B, C, D)


def _ntlm(data: bytes) -> str:
    """NTLM hash: MD4 of the password encoded UTF-16LE."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    return md4(text.encode("utf-16le")).hex()


def _crc32(data: bytes) -> str:
    return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")


def _adler32(data: bytes) -> str:
    return format(zlib.adler32(data) & 0xFFFFFFFF, "08x")


# --------------------------------------------------------------------------- #
# Algorithm registry (used by `hash` and `crack`)
# --------------------------------------------------------------------------- #
def _build_algorithms() -> Dict[str, Callable[[bytes], str]]:
    algos: Dict[str, Callable[[bytes], str]] = {}
    # Everything hashlib offers on this build, in a sensible display order.
    for name in (
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha3_224", "sha3_256", "sha3_384", "sha3_512",
        "sha512_224", "sha512_256",
        "blake2b", "blake2s", "ripemd160", "sm3",
    ):
        if name in hashlib.algorithms_available:
            algos[name] = (lambda n: (lambda d: hashlib.new(n, d).hexdigest()))(name)
    # Pure-python / stdlib extras that hashlib may not expose.
    algos["md4"] = lambda d: md4(d).hex()
    algos["ntlm"] = _ntlm
    algos["crc32"] = _crc32
    algos["adler32"] = _adler32
    return algos


ALGORITHMS: Dict[str, Callable[[bytes], str]] = _build_algorithms()

# The short list shown by `hash` when the user does not ask for --all.
COMMON_ALGOS: List[str] = [a for a in ("md5", "sha1", "sha256", "sha512") if a in ALGORITHMS]


def compute_hash(algo: str, data: bytes) -> str:
    """Return the lowercase hex digest of ``data`` under ``algo``.

    Raises ``ValueError`` for an unknown algorithm (with the supported list).
    """
    name = algo.lower()
    fn = ALGORITHMS.get(name)
    if fn is None:
        raise ValueError(
            f"unknown algorithm {algo!r}; supported: {', '.join(sorted(ALGORITHMS))}"
        )
    return fn(data)


def compute_all(data: bytes, names: Optional[List[str]] = None) -> List[Tuple[str, str]]:
    """Compute several digests; returns ``(algo, hexdigest)`` in registry order."""
    names = names or list(ALGORITHMS)
    out: List[Tuple[str, str]] = []
    for name in names:
        try:
            out.append((name, compute_hash(name, data)))
        except Exception:
            continue
    return out


# --------------------------------------------------------------------------- #
# Hash identification
# --------------------------------------------------------------------------- #
@dataclass
class HashGuess:
    """One hypothesis about which algorithm produced a digest."""

    name: str
    confidence: float
    note: str

    def __iter__(self):  # lets a Guess unpack straight into a table row
        return iter((self.name, f"{self.confidence:.0%}", self.note))


# Modular-crypt / structured prefixes — near-certain when they match.
_PREFIX_SIGS: List[Tuple[str, str, float, str]] = [
    ("$2a$", "bcrypt", 0.99, "Blowfish-based bcrypt ($2a$)"),
    ("$2b$", "bcrypt", 0.99, "bcrypt ($2b$, current)"),
    ("$2y$", "bcrypt", 0.99, "bcrypt ($2y$, PHP)"),
    ("$2x$", "bcrypt", 0.98, "bcrypt ($2x$, legacy)"),
    ("$argon2id$", "argon2id", 0.99, "Argon2id (PHC winner)"),
    ("$argon2i$", "argon2i", 0.99, "Argon2i"),
    ("$argon2d$", "argon2d", 0.99, "Argon2d"),
    ("$scrypt$", "scrypt", 0.95, "scrypt (PHC format)"),
    ("$7$", "scrypt", 0.85, "scrypt (Sun crypt $7$)"),
    ("$1$", "md5crypt", 0.97, "Unix md5-crypt ($1$)"),
    ("$5$", "sha256crypt", 0.97, "Unix sha256-crypt ($5$)"),
    ("$6$", "sha512crypt", 0.97, "Unix sha512-crypt ($6$)"),
    ("$sha1$", "sha1crypt", 0.9, "NetBSD sha1-crypt"),
    ("pbkdf2_sha256$", "django-pbkdf2-sha256", 0.9, "Django PBKDF2-SHA256"),
    ("pbkdf2_sha1$", "django-pbkdf2-sha1", 0.9, "Django PBKDF2-SHA1"),
    ("$pbkdf2-sha256$", "pbkdf2-sha256", 0.9, "passlib PBKDF2-SHA256"),
    ("$P$", "phpass", 0.9, "phpass (WordPress / phpBB3)"),
    ("$H$", "phpass", 0.85, "phpass (variant)"),
    ("{SSHA}", "ldap-ssha1", 0.9, "LDAP salted SHA-1 (base64)"),
    ("{SHA}", "ldap-sha1", 0.9, "LDAP SHA-1 (base64)"),
    ("{SMD5}", "ldap-smd5", 0.85, "LDAP salted MD5 (base64)"),
    ("sha256$", "django-sha256", 0.6, "Django legacy sha256 (salt$hash)"),
    ("sha1$", "django-sha1", 0.6, "Django legacy sha1 (salt$hash)"),
    ("0x", "mssql/hex-blob", 0.4, "hex blob (MSSQL 0x… or raw bytes)"),
]

# Bare-hex signatures keyed by hex-character count, most likely first.
_LENGTH_SIGS: Dict[int, List[Tuple[str, float, str]]] = {
    8: [("crc32", 0.5, "CRC-32 (8 hex) — also Adler-32 / FCS-16"),
        ("adler32", 0.35, "Adler-32")],
    16: [("mysql323", 0.5, "MySQL 3.x/OLD_PASSWORD (16 hex)"),
         ("crc64", 0.3, "CRC-64"), ("ripemd64", 0.15, "half-word digest")],
    32: [("md5", 0.75, "MD5 — by far the most common 32-hex digest"),
         ("ntlm", 0.6, "NTLM (Windows password hash)"),
         ("md4", 0.4, "MD4"), ("lm", 0.3, "LM hash (uppercased)"),
         ("ripemd128", 0.25, "RIPEMD-128"), ("md2", 0.15, "MD2"),
         ("md5(md5(x))", 0.2, "double-MD5 / md5-then-md5")],
    40: [("sha1", 0.75, "SHA-1 — most common 40-hex digest"),
         ("ripemd160", 0.4, "RIPEMD-160"),
         ("sha1(sha1(x))", 0.2, "double-SHA1"),
         ("tiger160", 0.2, "Tiger-160"), ("haval160", 0.15, "HAVAL-160")],
    56: [("sha224", 0.7, "SHA-224"), ("sha3_224", 0.5, "SHA3-224 / Keccak-224"),
         ("haval224", 0.15, "HAVAL-224")],
    64: [("sha256", 0.75, "SHA-256 — most common 64-hex digest"),
         ("sha3_256", 0.5, "SHA3-256 / Keccak-256"),
         ("blake2s", 0.35, "BLAKE2s-256"), ("sm3", 0.25, "SM3"),
         ("ripemd256", 0.2, "RIPEMD-256"),
         ("sha512_256", 0.2, "SHA-512/256")],
    96: [("sha384", 0.7, "SHA-384"), ("sha3_384", 0.5, "SHA3-384 / Keccak-384")],
    128: [("sha512", 0.75, "SHA-512 — most common 128-hex digest"),
          ("sha3_512", 0.5, "SHA3-512 / Keccak-512"),
          ("blake2b", 0.35, "BLAKE2b-512"), ("whirlpool", 0.3, "Whirlpool")],
}

_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_MYSQL41 = re.compile(r"^\*[0-9A-Fa-f]{40}$")


def identify_hashes(digest: str) -> List[HashGuess]:
    """Rank likely algorithms for ``digest`` from prefix, length and charset.

    Returns highest-confidence first.  Never raises; an unrecognised string
    yields a single low-confidence "unknown" guess.
    """
    s = digest.strip()
    guesses: List[HashGuess] = []
    if not s:
        return [HashGuess("unknown", 0.0, "empty input")]

    # 1. Structured prefixes (modular crypt format, LDAP, framework hashes).
    for pref, name, conf, note in _PREFIX_SIGS:
        if s.startswith(pref):
            guesses.append(HashGuess(name, conf, note))
    if guesses:
        return _dedup(guesses)

    # 2. MySQL 4.1+  ( *<40 hex> ).
    if _MYSQL41.match(s):
        return [HashGuess("mysql41", 0.9, "MySQL 4.1+  ( *<40 hex, upper> )")]

    # 3. Bare hex, keyed on length.
    t = re.sub(r"\s", "", s)
    if _HEX_ONLY.match(t):
        n = len(t)
        for name, conf, note in _LENGTH_SIGS.get(n, []):
            guesses.append(HashGuess(name, conf, note))
        if not guesses:
            if n % 2 == 0:
                guesses.append(HashGuess(
                    "unknown-hex", 0.2,
                    f"{n} hex chars ({n // 2} bytes) — no common digest of this length"))
            else:
                guesses.append(HashGuess(
                    "not-a-hash", 0.1,
                    f"{n} hex chars (odd length — unlikely a raw digest)"))
        return _dedup(guesses)

    # 4. Base64-ish blob (could be a raw/base64 digest or LDAP body).
    if re.match(r"^[A-Za-z0-9+/]+={0,2}$", t) and len(t) >= 16:
        guesses.append(HashGuess(
            "base64-digest?", 0.3,
            f"{len(t)} base64 chars — maybe a base64-encoded raw digest"))
        return guesses

    return [HashGuess("unknown", 0.1, "no recognised prefix, length or charset")]


def _dedup(guesses: List[HashGuess]) -> List[HashGuess]:
    """Sort by confidence desc, keeping the first (best) note per name."""
    seen = set()
    ordered = sorted(guesses, key=lambda g: g.confidence, reverse=True)
    out: List[HashGuess] = []
    for g in ordered:
        if g.name in seen:
            continue
        seen.add(g.name)
        out.append(g)
    return out


# --------------------------------------------------------------------------- #
# Dictionary cracking
# --------------------------------------------------------------------------- #
# Common password suffixes appended during mutation (kept short & high-yield).
_SUFFIXES = ["1", "2", "12", "123", "1234", "12345", "123456",
             "!", "1!", "123!", "@", "#", "00", "01", "07", "69",
             "007", "2023", "2024", "2025", "2026", "password"]


def mutations(word: str) -> Iterator[str]:
    """Yield ``word`` plus common case and suffix variants, de-duplicated."""
    seen: set = set()
    bases = [word, word.lower(), word.upper(), word.capitalize()]
    for b in bases:
        if b not in seen:
            seen.add(b)
            yield b
    for b in (word, word.lower(), word.capitalize()):
        for d in "0123456789":
            c = b + d
            if c not in seen:
                seen.add(c)
                yield c
        for suf in _SUFFIXES:
            c = b + suf
            if c not in seen:
                seen.add(c)
                yield c


ProgressCb = Callable[[int, bool], None]


def dictionary_crack(
    target_hex: str,
    algo: str,
    wordlist_path: str = DEFAULT_WORDLIST,
    *,
    with_mutations: bool = True,
    max_candidates: Optional[int] = None,
    progress_cb: Optional[ProgressCb] = None,
    progress_every: int = 250_000,
) -> Tuple[Optional[str], int]:
    """Try each wordlist entry (and mutations) against ``target_hex``.

    Returns ``(preimage, tried)`` — ``preimage`` is ``None`` if not found.
    ``progress_cb(tried, capped)`` is called every ``progress_every`` candidates
    and once more when the ``max_candidates`` cap is hit.
    """
    target = re.sub(r"\s", "", target_hex).lower()
    fn = ALGORITHMS.get(algo.lower())
    if fn is None:
        raise ValueError(f"unknown algorithm {algo!r}")

    tried = 0
    with open(wordlist_path, "r", encoding="latin-1", errors="replace") as fh:
        for line in fh:
            word = line.rstrip("\r\n")
            if not word:
                continue
            candidates = mutations(word) if with_mutations else iter((word,))
            for cand in candidates:
                tried += 1
                if fn(cand.encode("utf-8", "replace")) == target:
                    return cand, tried
                if max_candidates is not None and tried >= max_candidates:
                    if progress_cb:
                        progress_cb(tried, True)
                    return None, tried
                if progress_cb and tried % progress_every == 0:
                    progress_cb(tried, False)
    return None, tried


# --------------------------------------------------------------------------- #
# Pure-Python MD5 & SHA-1 with resumable state (for length extension)
# --------------------------------------------------------------------------- #
class _MD5:
    """MD5 that can start from an arbitrary internal state and byte count."""

    _S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + \
         [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
    _K = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]

    def __init__(self) -> None:
        self.a = 0x67452301
        self.b = 0xEFCDAB89
        self.c = 0x98BADCFE
        self.d = 0x10325476
        self.msg_len = 0  # bytes already absorbed (must be a multiple of 64)

    @staticmethod
    def padding(msg_byte_len: int) -> bytes:
        pad = b"\x80"
        pad += b"\x00" * ((56 - (msg_byte_len + 1) % 64) % 64)
        pad += struct.pack("<Q", (msg_byte_len * 8) & 0xFFFFFFFFFFFFFFFF)
        return pad

    def _chunk(self, block: bytes) -> None:
        a, b, c, d = self.a, self.b, self.c, self.d
        M = struct.unpack("<16I", block)
        for i in range(64):
            if i < 16:
                f = (b & c) | (~b & d)
                g = i
            elif i < 32:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16
            f = (f + a + self._K[i] + M[g]) & 0xFFFFFFFF
            a, d, c = d, c, b
            b = (b + _lrot(f, self._S[i])) & 0xFFFFFFFF
        self.a = (self.a + a) & 0xFFFFFFFF
        self.b = (self.b + b) & 0xFFFFFFFF
        self.c = (self.c + c) & 0xFFFFFFFF
        self.d = (self.d + d) & 0xFFFFFFFF

    def digest_hex(self, data: bytes) -> str:
        """Absorb ``data`` (from current state) with final padding; return hex."""
        total = self.msg_len + len(data)
        msg = data + self.padding(total)
        for i in range(0, len(msg), 64):
            self._chunk(msg[i:i + 64])
        return struct.pack("<4I", self.a, self.b, self.c, self.d).hex()

    @classmethod
    def from_digest(cls, digest_hex: str, absorbed: int) -> "_MD5":
        h = bytes.fromhex(digest_hex)
        obj = cls()
        obj.a, obj.b, obj.c, obj.d = struct.unpack("<4I", h)
        obj.msg_len = absorbed
        return obj


class _SHA1:
    """SHA-1 that can start from an arbitrary internal state and byte count."""

    def __init__(self) -> None:
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self.msg_len = 0

    @staticmethod
    def padding(msg_byte_len: int) -> bytes:
        pad = b"\x80"
        pad += b"\x00" * ((56 - (msg_byte_len + 1) % 64) % 64)
        pad += struct.pack(">Q", (msg_byte_len * 8) & 0xFFFFFFFFFFFFFFFF)
        return pad

    def _chunk(self, block: bytes) -> None:
        w = list(struct.unpack(">16I", block)) + [0] * 64
        for i in range(16, 80):
            w[i] = _lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
        a, b, c, d, e = self.h
        for i in range(80):
            if i < 20:
                f, k = (b & c) | (~b & d), 0x5A827999
            elif i < 40:
                f, k = b ^ c ^ d, 0x6ED9EBA1
            elif i < 60:
                f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                f, k = b ^ c ^ d, 0xCA62C1D6
            tmp = (_lrot(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e, d, c, b, a = d, c, _lrot(b, 30), a, tmp
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF

    def digest_hex(self, data: bytes) -> str:
        total = self.msg_len + len(data)
        msg = data + self.padding(total)
        for i in range(0, len(msg), 64):
            self._chunk(msg[i:i + 64])
        return "".join(f"{x:08x}" for x in self.h)

    @classmethod
    def from_digest(cls, digest_hex: str, absorbed: int) -> "_SHA1":
        h = bytes.fromhex(digest_hex)
        obj = cls()
        obj.h = list(struct.unpack(">5I", h))
        obj.msg_len = absorbed
        return obj


def md5_hex(data: bytes) -> str:
    """Pure-Python MD5 (matches ``hashlib.md5``)."""
    return _MD5().digest_hex(data)


def sha1_hex(data: bytes) -> str:
    """Pure-Python SHA-1 (matches ``hashlib.sha1``)."""
    return _SHA1().digest_hex(data)


_PADDERS = {"md5": _MD5.padding, "sha1": _SHA1.padding}
_RESUMERS = {"md5": _MD5.from_digest, "sha1": _SHA1.from_digest}


def glue_padding(algo: str, original_len: int) -> bytes:
    """The Merkle–Damgård padding that ``H`` appended after ``original_len`` bytes."""
    algo = algo.lower()
    if algo not in _PADDERS:
        raise ValueError("length extension supports only 'md5' and 'sha1'")
    return _PADDERS[algo](original_len)


def length_extension(
    algo: str,
    known_hash: str,
    data: bytes,
    append: bytes,
    keylen: int,
) -> Tuple[bytes, str]:
    """Forge a length-extended message and its digest.

    Given ``known_hash = H(secret ‖ data)`` where ``len(secret) == keylen`` (but
    ``secret`` itself is unknown), return ``(forged_suffix, new_hash)`` such that::

        H(secret ‖ forged_suffix) == new_hash
        forged_suffix == data + glue_padding + append

    Works by parsing ``known_hash`` back into ``H``'s internal registers, then
    resuming the compression from exactly the point the original message ended.
    """
    algo = algo.lower()
    if algo not in _RESUMERS:
        raise ValueError("length extension supports only 'md5' and 'sha1'")
    known = known_hash.strip().lower()
    expect = 32 if algo == "md5" else 40
    if not _HEX_ONLY.match(known) or len(known) != expect:
        raise ValueError(f"{algo} digest must be {expect} hex characters")

    original_len = keylen + len(data)
    glue = glue_padding(algo, original_len)
    absorbed = original_len + len(glue)  # a multiple of the 64-byte block size
    state = _RESUMERS[algo](known, absorbed)
    new_hash = state.digest_hex(append)
    forged = data + glue + append
    return forged, new_hash


def parse_keylen(spec: str) -> List[int]:
    """Parse a --keylen spec: ``16``, a range ``8-16`` / ``8:16``, or ``8,12,16``."""
    spec = spec.strip()
    if not spec:
        raise ValueError("empty --keylen")
    if "," in spec:
        return [int(x) for x in spec.split(",") if x.strip()]
    m = re.fullmatch(r"(\d+)\s*[-:]\s*(\d+)", spec)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        if hi < lo:
            lo, hi = hi, lo
        return list(range(lo, hi + 1))
    return [int(spec)]


# --------------------------------------------------------------------------- #
# CLI — hash-id
# --------------------------------------------------------------------------- #
@command(
    "hash-id",
    group="modern",
    summary="Identify likely hash algorithms from a digest's shape",
    manual="hashes",
    aliases=["hashid", "identify-hash"],
    args=io_args(positional="digest", positional_help="the hash to identify (hex, or $-prefixed crypt string)"),
    examples=[
        "aesop hash-id 5f4dcc3b5aa765d61d8327deb882cf99   # -> md5",
        "aesop hash-id '$2b$12$....'                       # -> bcrypt",
        "aesop hash-id da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "echo 8846f7eaee8fb117ad06bdd830b7586c | aesop hash-id",
    ],
    description="""
        Names the algorithm(s) that could have produced a digest, using its
        length, character set and any structured prefix ($2b$ bcrypt, $6$
        sha512-crypt, {SSHA} LDAP, and friends).  Guesses are ranked by how
        common each algorithm is at that length — md5 outranks ntlm at 32 hex,
        sha1 outranks ripemd-160 at 40, and so on.  The ranked algorithm names
        print first (one per line, pipe-friendly); a table with confidences and
        notes follows.
    """,
)
def cmd_hash_id(args, out) -> int:
    # Read the digest verbatim: it is an identifier, not data to be decoded.
    inp = io.load(args, encoding="raw")
    s = inp.text.strip()
    if not s:
        out.error("no hash provided (give a value, --file, or pipe via stdin)")
        return 2
    guesses = identify_hashes(s)
    for g in guesses:
        out.raw(g.name)
    out.print()
    out.table(
        ["algorithm", "confidence", "notes"],
        [tuple(g) for g in guesses],
        title=f"hash-id — {len(s)} chars",
    )
    top = guesses[0]
    if top.name in ALGORITHMS:
        out.hint(f"next:  aesop crack --algo {top.name} '{s}'   (unsalted only)")
    return 0


# --------------------------------------------------------------------------- #
# CLI — hash
# --------------------------------------------------------------------------- #
@command(
    "hash",
    group="modern",
    summary="Compute digests (md5/sha1/sha256/…/ntlm/crc32) of input",
    manual="hashes",
    aliases=["digest", "checksum"],
    args=io_args(positional="text", positional_help="data to hash (literal, --file or stdin)") + [
        arg("-a --algo", "algorithm to emit (e.g. sha256); omit for common set, or 'all'"),
        arg("--all", "show every supported algorithm", action="store_true"),
    ],
    examples=[
        "aesop hash -a md5 'hello'                # -> 5d41402abc4b2a76b9719d911017c592",
        "aesop hash 'password'                    # md5/sha1/sha256/sha512 table",
        "aesop hash --all 'secret'               # every algorithm",
        "aesop hash -a sha256 -f payload.bin      # digest a file",
    ],
    description="""
        Computes cryptographic digests of the input bytes.  With --algo NAME the
        single hex digest is printed with out.raw (clean for pipes); with --all
        (or --algo all) every supported algorithm is tabulated; with neither a
        common set (md5, sha1, sha256, sha512) is shown.  Beyond hashlib's
        algorithms the tool adds md4, ntlm (MD4 of UTF-16LE), crc32 and adler32.
        Input is always treated as raw bytes — never sniffed as hex/base64 — so
        text that merely looks encoded is hashed literally.
    """,
)
def cmd_hash(args, out) -> int:
    inp = io.load(args, encoding="raw")
    data = inp.data
    algo = (args.algo or "").strip()
    if algo and algo.lower() != "all":
        try:
            out.raw(compute_hash(algo, data))
        except ValueError as exc:
            out.error(str(exc))
            return 2
        return 0
    show_all = args.all or algo.lower() == "all"
    names = list(ALGORITHMS) if show_all else COMMON_ALGOS
    rows = compute_all(data, names)
    out.table(["algorithm", "digest"], rows, title=f"digests of {len(data)} bytes")
    return 0


# --------------------------------------------------------------------------- #
# CLI — crack
# --------------------------------------------------------------------------- #
@command(
    "crack",
    group="modern",
    summary="Dictionary-attack an unsalted hex digest (with mutations)",
    manual="hashes",
    aliases=["dehash"],
    args=io_args(positional="digest", positional_help="the hex digest to crack") + [
        arg("-a --algo", "hash algorithm (default: inferred from length)"),
        arg("-w --wordlist", f"wordlist path (default: {DEFAULT_WORDLIST})", metavar="PATH"),
        arg("--no-mutations", "try each word verbatim only (no case/suffix variants)",
            action="store_true"),
        arg("--max", "stop after this many candidates (0 = no cap)", type=int, default=0),
    ],
    examples=[
        "aesop crack -a md5 5f4dcc3b5aa765d61d8327deb882cf99   # -> password",
        "aesop crack 5d41402abc4b2a76b9719d911017c592          # infers md5",
        "aesop crack -a sha1 -w rockyou.txt <digest>",
        "echo <digest> | aesop crack -a sha256 --no-mutations",
    ],
    description="""
        Recovers the preimage of an unsalted hash by trying every word in a
        wordlist (default /usr/share/dict/words) plus cheap mutations: upper /
        lower / capitalised case, and each word with a trailing digit or a common
        suffix (123, !, 2025, …).  Give --algo, or let AESOP infer it from the
        digest length.  Progress and any cap are logged via hints; the recovered
        password is printed with out.raw.  This is for fast unsalted digests
        (md5/sha1/…); salted or slow hashes (bcrypt, sha512-crypt) are out of
        scope — identify those with 'aesop hash-id' and use a dedicated cracker.
    """,
)
def cmd_crack(args, out) -> int:
    inp = io.load(args, encoding="raw")
    target = re.sub(r"\s", "", inp.text).lower()
    if not target:
        out.error("no digest provided")
        return 2
    if not _HEX_ONLY.match(target):
        out.error("crack expects a hex digest (salted/crypt hashes are out of scope)")
        return 2

    algo = (args.algo or "").lower()
    if not algo:
        inferred = [g.name for g in identify_hashes(target) if g.name in ALGORITHMS]
        if not inferred:
            out.error(f"could not infer algorithm for a {len(target)}-hex digest; pass --algo")
            return 2
        algo = inferred[0]
        out.hint(f"no --algo given; assuming {algo} from length ({len(target)} hex chars)")
    if algo not in ALGORITHMS:
        out.error(f"unknown algorithm {algo!r}; try: {', '.join(sorted(ALGORITHMS))}")
        return 2

    wordlist = args.wordlist or DEFAULT_WORDLIST
    if not os.path.exists(wordlist):
        out.error(f"wordlist not found: {wordlist} (pass --wordlist PATH)")
        return 2

    out.hint(f"cracking {algo} against {wordlist}"
             + ("" if args.no_mutations else " (with case/suffix mutations)"))

    def _progress(tried: int, capped: bool) -> None:
        if capped:
            out.hint(f"reached cap of {tried:,} candidates — giving up")
        else:
            out.hint(f"… {tried:,} candidates tried")

    try:
        result, tried = dictionary_crack(
            target, algo, wordlist,
            with_mutations=not args.no_mutations,
            max_candidates=(args.max or None),
            progress_cb=_progress,
        )
    except OSError as exc:
        out.error(f"cannot read wordlist: {exc}")
        return 2

    if result is None:
        out.warn(f"no match after {tried:,} candidates")
        return 1
    out.success(f"cracked in {tried:,} tries")
    out.raw(result)
    return 0


# --------------------------------------------------------------------------- #
# CLI — length-extension
# --------------------------------------------------------------------------- #
@command(
    "length-extension",
    group="modern",
    summary="Forge H(secret‖data‖pad‖append) from a known digest (md5/sha1)",
    manual="hashes",
    aliases=["lenext", "hash-ext"],
    args=[
        arg("--algo", "hash function (md5 or sha1)", choices=["md5", "sha1"], default="md5"),
        arg("--hash", "the known digest  H(secret ‖ data)  (hex)", metavar="HEX"),
        arg("--data", "the known message bytes appended after the secret", default=""),
        arg("--append", "the bytes you want to append to the message", default=""),
        arg("--keylen", "secret length N, a range 8-16, or a list 8,12,16", metavar="N"),
    ],
    examples=[
        "aesop length-extension --algo md5 --hash <H> --data 'user=guest' --append '&admin=1' --keylen 16",
        "aesop length-extension --algo sha1 --hash <H> --data '...' --append '...' --keylen 8-24",
        "aesop length-extension --hash <md5> --data 'amount=100' --append '&admin=true' --keylen 12,16,20",
    ],
    description="""
        The classic Merkle–Damgård length-extension attack against MAC = H(secret
        ‖ message).  Knowing only the digest H(secret ‖ data) and the *length* of
        the secret (not the secret itself), it forges a new message  data ‖
        glue-padding ‖ append  together with its valid digest H(secret ‖ that).
        Applies to MD5 and SHA-1 (and other plain MD constructions); HMAC and the
        sponge-based SHA-3 are immune.  Pass a single --keylen, a range, or a
        list to sweep candidate secret lengths; each forgery prints the message
        (hex) and the new digest with out.raw so it pipes straight into an
        exploit.
    """,
)
def cmd_length_extension(args, out) -> int:
    algo = args.algo.lower()
    if not args.hash:
        out.error("--hash is required (the known digest of secret+data)")
        return 2
    if args.keylen is None:
        out.error("--keylen is required (the secret's length, a range, or a list)")
        return 2
    try:
        keylens = parse_keylen(args.keylen)
    except ValueError:
        out.error(f"could not parse --keylen {args.keylen!r} (use N, A-B, or A,B,C)")
        return 2
    if any(k < 0 for k in keylens):
        out.error("--keylen values must be non-negative")
        return 2

    data = (args.data or "").encode("utf-8", "surrogateescape")
    append = (args.append or "").encode("utf-8", "surrogateescape")

    results: List[Tuple[int, bytes, str]] = []
    try:
        for kl in keylens:
            forged, new_hash = length_extension(algo, args.hash, data, append, kl)
            results.append((kl, forged, new_hash))
    except ValueError as exc:
        out.error(str(exc))
        return 2

    if len(results) == 1:
        kl, forged, new_hash = results[0]
        out.raw(forged.hex())
        out.raw(new_hash)
        glue = glue_padding(algo, kl + len(data))
        out.print()
        out.keyval(
            [
                ("algorithm", algo),
                ("assumed secret length", kl),
                ("forged message len", f"{len(forged)} bytes"),
                ("glue padding", f"{len(glue)} bytes"),
                ("new digest", new_hash),
            ],
            title="length-extension forgery",
        )
        out.hint("send the forged message (hex above) and the new digest to the oracle")
    else:
        for kl, forged, new_hash in results:
            out.raw(f"{kl}\t{forged.hex()}\t{new_hash}")
        out.print()
        out.table(
            ["keylen", "new digest", "forged message (hex)"],
            [(kl, new_hash, _short(forged.hex())) for kl, forged, new_hash in results],
            title=f"length-extension — {len(results)} candidate secret lengths",
        )
        out.hint("one row is correct — try each new-digest/message pair against the oracle")
    return 0


def _short(s: str, width: int = 48) -> str:
    return s if len(s) <= width else s[: width - 1] + "…"

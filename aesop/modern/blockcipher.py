"""
aesop.modern.blockcipher — educational block-cipher-mode analysis.

Block ciphers (AES, DES, …) are secure primitives, but the *mode* that chains
their blocks together is where practical attacks live.  This module implements
the two teaching-classic weaknesses that appear in almost every CTF and every
"crypto gone wrong" postmortem, working purely on ciphertext **bytes**:

* **ECB detection** — Electronic-Codebook mode encrypts each block
  independently, so identical plaintext blocks become identical ciphertext
  blocks.  That fingerprint (the famous "ECB penguin") is visible directly in the
  ciphertext: count repeated aligned blocks and you have caught it.
* **The CBC padding oracle** — if a system merely tells you *whether* a
  ciphertext had valid PKCS#7 padding, that one bit of feedback is enough to
  decrypt the whole message byte by byte, with no key.  We also give the
  **CBC bit-flip** primitive that lets you tamper with a chosen plaintext block.

Like every AESOP technique module this splits cleanly into

1. a pure, importable **programmatic API** on ``bytes`` (no printing, fully
   unit-testable — the oracle is just a ``Callable[[bytes], bool]``), and
2. a thin **CLI handler** that only marshals arguments, loads input and presents
   results via the shared :class:`aesop.ui.Output`.

The CLI's ``--oracle`` mode runs an **external, user-supplied local program** as
the padding oracle — the standard CTF pattern where you point AESOP at the
challenge's own checker script.  Nothing here breaks real, correctly implemented
cryptography; it demonstrates why mode and padding choices matter.
"""
from __future__ import annotations

import subprocess
from collections import Counter
from typing import Callable, List, Optional, Tuple, Union

from ..registry import command, arg, io_args
from ..core import io
from ..core.score import printable_ratio

BytesLike = Union[bytes, bytearray, str]

# An oracle is any callable that takes a ciphertext and answers "valid padding?".
Oracle = Callable[[bytes], bool]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _as_bytes(x: BytesLike) -> bytes:
    """Coerce ``str``/``bytearray``/``bytes`` to ``bytes`` (str via UTF-8)."""
    if isinstance(x, str):
        return x.encode("utf-8")
    return bytes(x)


def xor_bytes(a: BytesLike, b: BytesLike) -> bytes:
    """XOR two equal-length byte strings (raises if the lengths differ)."""
    a = _as_bytes(a)
    b = _as_bytes(b)
    if len(a) != len(b):
        raise ValueError("xor operands must be the same length")
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data: BytesLike, block: int = 16) -> List[bytes]:
    """Slice ``data`` into ``block``-byte chunks (the trailing chunk may be short)."""
    data = _as_bytes(data)
    if block <= 0:
        raise ValueError("block size must be positive")
    return [data[i : i + block] for i in range(0, len(data), block)]


# --------------------------------------------------------------------------- #
# PKCS#7 padding
# --------------------------------------------------------------------------- #
def pkcs7_pad(data: BytesLike, block: int = 16) -> bytes:
    """Append PKCS#7 padding so the result is a whole number of blocks.

    The pad value equals the number of bytes added (1..``block``); when the input
    is already block-aligned a *full* block of padding is added, as the standard
    requires (so unpadding is always unambiguous).
    """
    data = _as_bytes(data)
    if not 0 < block < 256:
        raise ValueError("block size must be in 1..255 for PKCS#7")
    padlen = block - (len(data) % block)
    return data + bytes([padlen]) * padlen


def pkcs7_unpad(data: BytesLike, block: int = 16) -> bytes:
    """Strip and validate PKCS#7 padding; raise ``ValueError`` if it is invalid.

    This is exactly the check a vulnerable server performs — see
    :func:`pkcs7_valid` for the boolean form used to build a padding oracle.
    """
    data = _as_bytes(data)
    if not 0 < block < 256:
        raise ValueError("block size must be in 1..255 for PKCS#7")
    if not data or len(data) % block != 0:
        raise ValueError("data length is not a positive multiple of the block size")
    padlen = data[-1]
    if padlen < 1 or padlen > block:
        raise ValueError("invalid PKCS#7 padding (bad length byte)")
    if data[-padlen:] != bytes([padlen]) * padlen:
        raise ValueError("invalid PKCS#7 padding (bytes do not match)")
    return data[:-padlen]


def pkcs7_valid(data: BytesLike, block: int = 16) -> bool:
    """``True`` iff ``data`` carries well-formed PKCS#7 padding.

    The one bit of information a padding oracle leaks.  Wrap this (or a remote
    check that behaves like it) as :data:`Oracle` and hand it to
    :func:`padding_oracle_decrypt`.
    """
    try:
        pkcs7_unpad(data, block)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# ECB detection
# --------------------------------------------------------------------------- #
def detect_ecb(data: BytesLike, block: int = 16) -> Tuple[bool, int]:
    """Detect ECB mode by counting repeated aligned ciphertext blocks.

    In ECB each plaintext block is encrypted independently, so any two identical
    plaintext blocks (a run of spaces, a repeated field, the ECB penguin) become
    identical ciphertext blocks.  Random/CBC ciphertext essentially never repeats
    a full 16-byte block.

    Returns ``(is_ecb, repeated_block_count)`` where ``repeated_block_count`` is
    the number of blocks that duplicate an earlier one (i.e. total blocks minus
    distinct blocks); any repeat at all is a strong ECB signal.
    """
    blocks = split_blocks(data, block)
    # Only count full-width blocks — a short trailing chunk cannot be compared.
    full = [b for b in blocks if len(b) == block]
    counts = Counter(full)
    repeated = sum(c - 1 for c in counts.values() if c > 1)
    return repeated > 0, repeated


def repeated_blocks(data: BytesLike, block: int = 16) -> List[Tuple[str, int]]:
    """Return ``(block_hex, count)`` for every block that appears more than once,
    most-repeated first — the raw evidence behind :func:`detect_ecb`."""
    counts = Counter(b for b in split_blocks(data, block) if len(b) == block)
    dupes = [(b.hex(), c) for b, c in counts.items() if c > 1]
    dupes.sort(key=lambda t: t[1], reverse=True)
    return dupes


def find_block_size(data: BytesLike,
                    candidates: Tuple[int, ...] = (16, 8, 32)) -> Optional[int]:
    """Guess the cipher block size from repetition.

    For each plausible block size that divides the ciphertext length we measure
    the fraction of aligned blocks that repeat; the true block size maximises it.
    Ties favour the larger size (so genuine AES ciphertext reports 16 rather than
    8).  Returns the best block size, or ``None`` if nothing repeats (in which
    case the mode is probably not ECB and any block size is equally plausible).
    """
    data = _as_bytes(data)
    best: Optional[int] = None
    best_key: Tuple[float, int] = (0.0, -1)
    for b in candidates:
        if b <= 0 or len(data) < 2 * b or len(data) % b != 0:
            continue
        nblocks = len(data) // b
        _, reps = detect_ecb(data, b)
        frac = reps / nblocks
        key = (frac, b)
        if frac > 0 and key > best_key:
            best_key = key
            best = b
    return best


# --------------------------------------------------------------------------- #
# CBC bit-flipping
# --------------------------------------------------------------------------- #
def cbc_bitflip(known: BytesLike, desired: BytesLike, *,
                offset: int = 0, block: int = 16) -> bytes:
    """Compute the XOR mask to apply to the *previous* ciphertext block.

    In CBC, ``P_i = D_k(C_i) XOR C_{i-1}``, so tampering with a byte of the
    previous ciphertext block ``C_{i-1}`` flips exactly the corresponding byte of
    the current plaintext block ``P_i`` (while scrambling ``P_{i-1}`` beyond
    recognition — the attacker's tolerated cost).  If you currently know that a
    slice of ``P_i`` decodes to ``known`` and you want it to decode to
    ``desired``, XOR ``C_{i-1}`` with ``known XOR desired``.

    ``known`` and ``desired`` must be equal length and fit within the block at
    ``offset``.  Returns a full ``block``-length mask (zero outside the changed
    region) ready to XOR onto ``C_{i-1}`` — flip the *IV* instead when the target
    is the very first block.
    """
    known = _as_bytes(known)
    desired = _as_bytes(desired)
    if len(known) != len(desired):
        raise ValueError("known and desired must be the same length")
    if offset < 0 or offset + len(known) > block:
        raise ValueError("known/desired do not fit within the block at offset")
    mask = bytearray(block)
    for i, (k, d) in enumerate(zip(known, desired)):
        mask[offset + i] = k ^ d
    return bytes(mask)


# --------------------------------------------------------------------------- #
# CBC padding oracle
# --------------------------------------------------------------------------- #
def padding_oracle_decrypt(oracle: Oracle, ciphertext: BytesLike,
                           block: int = 16, iv: Optional[BytesLike] = None) -> bytes:
    """Decrypt CBC ciphertext using only a PKCS#7 padding oracle — no key.

    ``oracle`` is any callable ``oracle(ciphertext_bytes) -> bool`` that reports
    whether a ciphertext decrypts to valid PKCS#7 padding (see
    :func:`pkcs7_valid` to build one, or the CLI's ``--oracle`` to wrap an
    external program).

    The attack recovers each block byte-by-byte from last to first.  For the
    target block ``C_i`` we forge the preceding block so the plaintext ends in
    valid padding of a chosen length; a valid response reveals one byte of the
    intermediate state ``D_k(C_i)``, and XORing that with the *real* previous
    block yields the plaintext.  A perturb-and-recheck step disambiguates the
    lone false positive that can occur while recovering the final byte.

    Pass ``iv`` (one block) to also recover the first plaintext block; without it
    the first block is used only as the chain value and its plaintext is skipped.
    Returns the recovered plaintext **including** its trailing PKCS#7 padding —
    run it through :func:`pkcs7_unpad` for the clean message.
    """
    ct = _as_bytes(ciphertext)
    if block <= 0:
        raise ValueError("block size must be positive")
    if len(ct) == 0 or len(ct) % block != 0:
        raise ValueError("ciphertext length must be a positive multiple of the block size")

    blocks = split_blocks(ct, block)
    if iv is not None:
        iv = _as_bytes(iv)
        if len(iv) != block:
            raise ValueError("iv must be exactly one block long")
        blocks = [iv] + blocks
    if len(blocks) < 2:
        raise ValueError("need at least two blocks (or supply iv=) to decrypt")

    recovered = bytearray()
    for bi in range(1, len(blocks)):
        prev = blocks[bi - 1]
        target = blocks[bi]
        inter = bytearray(block)  # D_k(target): the cipher's raw block-decrypt

        for pad in range(1, block + 1):
            pos = block - pad
            forged = bytearray(block)
            # Force the already-known tail to decrypt to the padding value.
            for k in range(pos + 1, block):
                forged[k] = inter[k] ^ pad

            found = False
            for guess in range(256):
                forged[pos] = guess
                if not oracle(bytes(forged) + target):
                    continue
                # Guard against a false hit while attacking the final byte
                # (pad == 1): perturb the byte just before pos and re-ask. Real
                # single-byte padding stays valid; a longer accidental match
                # (e.g. the block already ended in 0x02 0x02) breaks.
                if pos > 0:
                    probe = bytearray(forged)
                    probe[pos - 1] ^= 0xFF
                    if not oracle(bytes(probe) + target):
                        continue
                inter[pos] = guess ^ pad
                found = True
                break

            if not found:
                raise RuntimeError(
                    f"padding oracle returned no valid byte at block {bi}, "
                    f"position {pos} — is the oracle correct and the block size {block}?"
                )

        recovered.extend(inter[k] ^ prev[k] for k in range(block))

    return bytes(recovered)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _shell_oracle(template: str, timeout: float) -> Oracle:
    """Wrap an external local command as a padding oracle.

    ``{}`` in ``template`` is replaced with the lowercase hex of the ciphertext.
    Validity is decided from the command's output/exit status:

    * stdout mentions ``invalid``  -> invalid,
    * else stdout mentions ``valid`` -> valid,
    * else exit code 0 -> valid, non-zero -> invalid.

    This is a LOCAL, user-supplied program run with the shell; only point it at a
    checker you trust.
    """
    if "{}" not in template:
        raise ValueError("--oracle command must contain '{}' where the hex ciphertext goes")

    def oracle(ct: bytes) -> bool:
        cmd = template.replace("{}", ct.hex())
        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        out_l = (proc.stdout or b"").lower()
        if b"invalid" in out_l:
            return False
        if b"valid" in out_l:
            return True
        return proc.returncode == 0

    return oracle


def _render_bytes(data: bytes) -> str:
    """Primary-output rendering: text if it looks printable, else hex."""
    if printable_ratio(data) > 0.9:
        return data.decode("latin-1")
    return data.hex()


@command(
    "blockcipher",
    group="modern",
    summary="Analyse block-cipher modes: ECB detection & CBC padding-oracle decrypt",
    manual="blockcipher",
    aliases=["block"],
    args=io_args(
        positional="ciphertext",
        positional_help="the ciphertext to analyse (hex/base64/raw auto-detected)",
    ) + [
        arg("--ecb-detect", "scan for repeated aligned blocks (ECB fingerprint)",
            action="store_true"),
        arg("--oracle", "external command that reports PKCS#7 validity; '{}' is "
            "replaced with the hex ciphertext (padding-oracle decrypt)",
            metavar="'CMD {}'"),
        arg("--block", "cipher block size in bytes", type=int, default=16),
        arg("--iv", "IV (hex) — supply it to also recover the first block via --oracle"),
        arg("--oracle-timeout", "per-query timeout for --oracle, seconds",
            type=float, default=30.0),
    ],
    examples=[
        "aesop blockcipher --ecb-detect 0011223344556677889900112233445500112233445566778899001122334455",
        "cat cipher.hex | aesop block --ecb-detect",
        "aesop blockcipher --oracle './oracle.sh {}' 9f0b...   # byte-at-a-time CBC decrypt",
        "aesop blockcipher --oracle 'python3 check.py {}' --iv 00000000000000000000000000000000 c1d2...",
    ],
    description="""
        Educational block-cipher-mode analysis, straight from the cryptopals
        playbook.  With --ecb-detect (the default) AESOP splits the ciphertext
        into aligned blocks and looks for repeats — the tell-tale sign of ECB,
        where identical plaintext blocks leak as identical ciphertext blocks.
        With --oracle it mounts the classic CBC padding-oracle attack: point it at
        an external program that reveals only whether padding is valid, and AESOP
        recovers the plaintext one byte at a time, no key required.  The --oracle
        command is a LOCAL program you supply (the standard CTF pattern); '{}' is
        substituted with the hex ciphertext for each of the many probes.
    """,
)
def cmd_blockcipher(args, out) -> int:
    inp = io.load(args)
    data = inp.data
    if not data:
        out.error("no input (give a value, --file, or pipe via stdin)")
        return 1

    block = args.block
    if block <= 0:
        out.error("--block must be positive")
        return 1

    # ------------------------------------------------------------------ #
    # Padding-oracle decryption
    # ------------------------------------------------------------------ #
    if args.oracle:
        if len(data) % block != 0:
            out.error(f"ciphertext length {len(data)} is not a multiple of block size {block}")
            return 1
        iv = None
        if args.iv:
            try:
                iv = bytes.fromhex(args.iv.strip())
            except ValueError:
                out.error("--iv is not valid hex")
                return 1
            if len(iv) != block:
                out.error(f"--iv must be exactly {block} bytes ({block * 2} hex chars)")
                return 1
        try:
            oracle = _shell_oracle(args.oracle, args.oracle_timeout)
        except ValueError as exc:
            out.error(str(exc))
            return 1

        out.warn("running a LOCAL, user-supplied oracle command — probes may take a while")
        out.info(f"attacking {len(data) // block} block(s), block size {block}"
                 + (" (with IV)" if iv is not None else ""))
        try:
            recovered = padding_oracle_decrypt(oracle, data, block=block, iv=iv)
        except (RuntimeError, ValueError) as exc:
            out.error(str(exc))
            out.hint("check that the command really is a padding oracle and the block size is right")
            return 1

        try:
            plain = pkcs7_unpad(recovered, block)
            padded = True
        except ValueError:
            plain = recovered  # keep whatever we recovered if padding looks off
            padded = False

        out.success(f"recovered {len(plain)} bytes"
                    + ("" if padded else " (PKCS#7 unpad failed — showing raw recovery)"))
        out.raw(_render_bytes(plain))
        return 0

    # ------------------------------------------------------------------ #
    # ECB detection (default)
    # ------------------------------------------------------------------ #
    guessed = find_block_size(data)
    scan_block = guessed or block
    is_ecb, reps = detect_ecb(data, scan_block)
    nblocks = len(data) // scan_block if scan_block else 0

    if is_ecb:
        out.success(f"ECB likely — {reps} repeated block(s) at block size {scan_block}")
    else:
        out.info(f"no repeated aligned blocks at block size {scan_block} — ECB unlikely")

    # Pipe-friendly primary result line.
    out.raw(f"ecb={'yes' if is_ecb else 'no'} block={scan_block} "
            f"repeated_blocks={reps} total_blocks={nblocks}")

    # Diagnostics: how each candidate block size scores.
    rows = []
    for b in (8, 16, 32):
        if len(data) < 2 * b or len(data) % b != 0:
            continue
        _, r = detect_ecb(data, b)
        total = len(data) // b
        rows.append((b, total, r, f"{(r / total):.2%}" if total else "-"))
    if rows:
        out.print()
        out.table(
            ["block size", "blocks", "repeats", "repeat rate"],
            rows,
            title="ECB scan (repeats across candidate block sizes)",
        )

    dupes = repeated_blocks(data, scan_block)
    if dupes:
        out.print()
        out.table(
            ["repeated block (hex)", "occurrences"],
            [(h if len(h) <= 40 else h[:39] + "…", c) for h, c in dupes[:8]],
            title=f"duplicate blocks at size {scan_block}",
        )
        out.hint("repeated ciphertext blocks == repeated plaintext blocks -> ECB")
    return 0

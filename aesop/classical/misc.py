"""
aesop.classical.misc — the fox's book of small, fixed alphabets.

A grab-bag of classical *substitution and representation* schemes that are too
small to each deserve a file of their own, yet turn up constantly as the first
or last layer of a CTF challenge:

* **atbash**  — the Hebrew mirror alphabet (A↔Z); a keyless involution.
* **rot47**   — ROT-13's cousin over the 94 printable ASCII glyphs; involution.
* **morse**   — International Morse code (letters, digits, punctuation).
* **bacon**   — Bacon's 5-bit steganographic alphabet (24- and 26-letter forms).
* **a1z26**   — the schoolyard "letter = position" numbering (A=1 … Z=26).
* **reverse** — the plain string reversal that hides in many multi-layer puzzles.

Like every AESOP technique module (see :mod:`aesop.classical.caesar`) this file
keeps two halves apart:

1. A **programmatic API** — pure functions on ``str`` with no printing — that is
   importable and unit-testable.
2. **Command handlers** wired into the CLI via :func:`aesop.registry.command`,
   which only marshal arguments, load input and present results.

None of these schemes has a key or a keyspace worth searching: the whole game is
knowing *which* fixed alphabet you are looking at.  So every command here is a
direct, deterministic transform whose primary result is emitted with
``out.raw(...)`` to stay pipe-friendly.

**A note on input handling.**  Unlike the cipher-breakers, every command in this
module treats its input as *literal text* — the string itself is the data.  We
therefore load with ``encoding="raw"`` on both encode and decode paths and never
run the input through the hex/base64 sniffer, which would happily mangle a run of
Baconian ``A``/``B`` (valid hex) or an A1Z26 digit stream (also valid hex) into
bytes.  See the ``deviations`` note that shipped with this module.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ..registry import command, arg, io_args
from ..core import io

A_UP = ord("A")
Z_UP = ord("Z")
A_LO = ord("a")
Z_LO = ord("z")


# --------------------------------------------------------------------------- #
# Atbash
# --------------------------------------------------------------------------- #
def atbash(text: str) -> str:
    """Apply the Atbash mirror alphabet: A↔Z, B↔Y, … (case preserved).

    Atbash is a fixed monoalphabetic substitution defined by ``c = 25 − p`` on
    letter indices, which makes it a self-inverse *involution*: applying it twice
    returns the original.  Non-letters pass through unchanged.

    >>> atbash("HELLO")
    'SVOOL'
    >>> atbash(atbash("Attack at dawn!"))
    'Attack at dawn!'
    """
    out: List[str] = []
    for ch in text:
        o = ord(ch)
        if A_UP <= o <= Z_UP:
            out.append(chr(Z_UP - (o - A_UP)))
        elif A_LO <= o <= Z_LO:
            out.append(chr(Z_LO - (o - A_LO)))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------- #
# ROT47
# --------------------------------------------------------------------------- #
_ROT47_LO = 33   # '!'
_ROT47_HI = 126  # '~'
_ROT47_SPAN = _ROT47_HI - _ROT47_LO + 1  # 94


def rot47(text: str) -> str:
    """Rotate every printable-ASCII glyph (``!``–``~``) by 47 places.

    ROT47 is ROT13 generalised to the 94 printable ASCII characters
    (codepoints 33–126), so it also scrambles digits and punctuation.  Because
    the alphabet size is 94 and the rotation is exactly half of it, ROT47 is its
    own inverse.  Space (32) and control characters pass through unchanged.

    >>> rot47("Hello, World!")
    'w6==@[ (@C=5P'
    >>> rot47(rot47("Hello, World!"))
    'Hello, World!'
    """
    out: List[str] = []
    for ch in text:
        o = ord(ch)
        if _ROT47_LO <= o <= _ROT47_HI:
            out.append(chr(_ROT47_LO + (o - _ROT47_LO + 47) % _ROT47_SPAN))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------- #
# International Morse code
# --------------------------------------------------------------------------- #
#: char → morse code.  Letters, digits and the standard punctuation set.
MORSE_CODE: Dict[str, str] = {
    "A": ".-",    "B": "-...",  "C": "-.-.",  "D": "-..",   "E": ".",
    "F": "..-.",  "G": "--.",   "H": "....",  "I": "..",    "J": ".---",
    "K": "-.-",   "L": ".-..",  "M": "--",    "N": "-.",    "O": "---",
    "P": ".--.",  "Q": "--.-",  "R": ".-.",   "S": "...",   "T": "-",
    "U": "..-",   "V": "...-",  "W": ".--",   "X": "-..-",  "Y": "-.--",
    "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--",
    "/": "-..-.",  "(": "-.--.",  ")": "-.--.-", "&": ".-...",  ":": "---...",
    ";": "-.-.-.", "=": "-...-",  "+": ".-.-.",  "-": "-....-", "_": "..--.-",
    '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
}

#: morse code → char (inverse of :data:`MORSE_CODE`; the mapping is 1-to-1).
MORSE_DECODE: Dict[str, str] = {code: ch for ch, code in MORSE_CODE.items()}

_LETTER_SEP = " "     # between letters within a word
_WORD_SEP = " / "     # between words


def morse_encode(text: str, letter_sep: str = _LETTER_SEP, word_sep: str = _WORD_SEP) -> str:
    """Encode ``text`` to International Morse.

    Letters within a word are joined by a single space; words (runs separated by
    whitespace in the input) are joined by ``/``.  Case is ignored and any
    character with no Morse mapping is silently skipped.

    >>> morse_encode("SOS")
    '... --- ...'
    >>> morse_encode("HELLO WORLD")
    '.... . .-.. .-.. --- / .-- --- .-. .-.. -..'
    """
    words_out: List[str] = []
    for word in text.split():
        letters = [MORSE_CODE[ch] for ch in word.upper() if ch in MORSE_CODE]
        if letters:
            words_out.append(letter_sep.join(letters))
    return word_sep.join(words_out)


def morse_decode(code: str) -> str:
    """Decode International Morse back to text (returns upper-case letters).

    Accepts ``/`` (optionally surrounded by spaces) as the word separator and
    runs of ``.``/``-`` separated by whitespace as letters.  Unknown symbols are
    skipped.  Inverse of :func:`morse_encode` up to letter case.

    >>> morse_decode("... --- ...")
    'SOS'
    >>> morse_decode(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")
    'HELLO WORLD'
    """
    words_out: List[str] = []
    for word in re.split(r"\s*/\s*", code.strip()):
        letters = [MORSE_DECODE[sym] for sym in word.split() if sym in MORSE_DECODE]
        if letters:
            words_out.append("".join(letters))
    return " ".join(words_out)


# --------------------------------------------------------------------------- #
# Baconian cipher
# --------------------------------------------------------------------------- #
def _bacon_table(variant: str) -> Dict[str, str]:
    """Build the letter→5-bit A/B table for the ``"24"`` or ``"26"`` variant.

    The 26-letter variant gives every letter a distinct code (A=aaaaa … Z=bbaab)
    and round-trips losslessly.  The classic 24-letter variant merges I/J and
    U/V onto a single code each, exactly as Francis Bacon published it, so those
    pairs cannot be told apart on decode.
    """
    if variant == "26":
        return {chr(A_UP + i): format(i, "05b").replace("0", "A").replace("1", "B")
                for i in range(26)}
    if variant == "24":
        # 24 distinct codes 0..23; I shares J's code, U shares V's.
        order = "ABCDEFGHIKLMNOPQRSTUWXYZ"  # note: no J, no V
        table: Dict[str, str] = {}
        for i, ch in enumerate(order):
            table[ch] = format(i, "05b").replace("0", "A").replace("1", "B")
        table["J"] = table["I"]
        table["V"] = table["U"]
        return table
    raise ValueError(f"unknown Baconian variant {variant!r}; use '24' or '26'")


def bacon_encode(text: str, variant: str = "26", group_sep: str = " ") -> str:
    """Encode ``text`` as groups of five ``A``/``B`` symbols (Baconian).

    Only letters are encoded; case is ignored and non-letters are skipped.
    Groups are joined by ``group_sep`` (a space by default) for readability.

    >>> bacon_encode("HELLO")
    'AABBB AABAA ABABB ABABB ABBBA'
    """
    table = _bacon_table(variant)
    groups = [table[ch] for ch in text.upper() if ch in table]
    return group_sep.join(groups)


def bacon_decode(code: str, variant: str = "26") -> str:
    """Decode a Baconian ``A``/``B`` (or ``0``/``1``) stream back to letters.

    Whitespace and any characters other than the two group symbols are ignored;
    ``0``/``1`` are accepted as aliases for ``A``/``B``.  The symbol stream is
    read in fixed groups of five.  A trailing partial group is dropped.

    >>> bacon_decode("AABBB AABAA ABABB ABABB ABBBA")
    'HELLO'
    """
    table = _bacon_table(variant)
    # First-occurrence wins so a merged 24-letter code decodes to its canonical
    # member (I over J, U over V), which are inserted before their partners.
    inverse: Dict[str, str] = {}
    for ch, bits_ in table.items():
        inverse.setdefault(bits_, ch)
    norm = code.upper().replace("0", "A").replace("1", "B")
    bits = re.sub(r"[^AB]", "", norm)
    usable = len(bits) - (len(bits) % 5)  # drop any trailing partial group
    out: List[str] = []
    for i in range(0, usable, 5):
        out.append(inverse.get(bits[i:i + 5], "?"))
    return "".join(out)


# --------------------------------------------------------------------------- #
# A1Z26
# --------------------------------------------------------------------------- #
def a1z26_encode(text: str, sep: str = " ", word_sep: str = " / ") -> str:
    """Encode letters to their alphabet positions (A=1 … Z=26).

    Numbers within a word are joined by ``sep``; words (whitespace-separated runs
    in the input) are joined by ``word_sep``.  Non-letters are skipped.

    >>> a1z26_encode("HELLO")
    '8 5 12 12 15'
    >>> a1z26_encode("HELLO WORLD")
    '8 5 12 12 15 / 23 15 18 12 4'
    """
    words_out: List[str] = []
    for word in text.split():
        nums = [str(ord(ch) - A_UP + 1) for ch in word.upper() if "A" <= ch.upper() <= "Z"]
        if nums:
            words_out.append(sep.join(nums))
    return word_sep.join(words_out)


def a1z26_decode(text: str) -> str:
    """Decode a stream of 1–26 numbers back to upper-case letters.

    The parser is separator-agnostic: it splits words on ``/`` and then extracts
    every run of digits, so any separator used on encode round-trips.  A number
    outside 1–26 raises :class:`ValueError`.

    >>> a1z26_decode("8 5 12 12 15")
    'HELLO'
    >>> a1z26_decode("8 5 12 12 15 / 23 15 18 12 4")
    'HELLO WORLD'
    """
    words_out: List[str] = []
    for word in text.split("/"):
        letters: List[str] = []
        for tok in re.findall(r"\d+", word):
            n = int(tok)
            if not 1 <= n <= 26:
                raise ValueError(f"number {n} out of range (A1Z26 expects 1–26)")
            letters.append(chr(A_UP + n - 1))
        if letters:
            words_out.append("".join(letters))
    return " ".join(words_out)


# --------------------------------------------------------------------------- #
# Reverse
# --------------------------------------------------------------------------- #
def reverse_text(text: str) -> str:
    """Return ``text`` reversed character-for-character (a self-inverse op).

    >>> reverse_text("HELLO")
    'OLLEH'
    >>> reverse_text(reverse_text("Attack at dawn"))
    'Attack at dawn'
    """
    return text[::-1]


# =========================================================================== #
# CLI handlers
# =========================================================================== #
# Every handler loads input as raw literal text (see the module docstring): these
# are character transforms, so the string itself is the data and must never be
# run through the hex/base64 sniffer.
# --------------------------------------------------------------------------- #
@command(
    "atbash",
    group="classical",
    summary="Apply the Atbash mirror cipher (A↔Z); self-inverse",
    manual="misc",
    aliases=["mirror"],
    args=io_args(positional="text", positional_help="text to transform"),
    examples=[
        "aesop atbash 'HELLO'                  # -> SVOOL",
        "aesop atbash 'SVOOL'                  # -> HELLO (same op decodes)",
        "echo 'Gsv jfrxp yildm ulc' | aesop atbash",
    ],
    description="""
        Atbash maps each letter to its mirror image in the alphabet (A↔Z, B↔Y,
        …), i.e. c = 25 − p.  It has no key and is its own inverse, so a single
        invocation both encodes and decodes.  Case and non-letters are preserved.
    """,
)
def cmd_atbash(args, out) -> int:
    inp = io.load(args, encoding="raw")
    out.raw(atbash(inp.text))
    return 0


@command(
    "rot47",
    group="classical",
    summary="Apply ROT47 over printable ASCII (!–~); self-inverse",
    manual="misc",
    args=io_args(positional="text", positional_help="text to transform"),
    examples=[
        "aesop rot47 'Hello, World!'           # -> w6==@[ (@C=5P",
        "aesop rot47 'w6==@[ (@C=5P'           # same op decodes",
        "echo 'The quick brown fox' | aesop rot47",
    ],
    description="""
        ROT47 rotates each of the 94 printable ASCII characters (codepoints
        33–126) by 47 places — ROT13 extended to digits and punctuation.  Because
        47 is exactly half of 94, ROT47 is its own inverse.  Space and control
        characters are left untouched.
    """,
)
def cmd_rot47(args, out) -> int:
    inp = io.load(args, encoding="raw")
    out.raw(rot47(inp.text))
    return 0


@command(
    "morse",
    group="classical",
    summary="Encode or decode International Morse code",
    manual="misc",
    aliases=["cw"],
    args=io_args(positional="text", positional_help="text to encode (or Morse to decode)") + [
        arg("-d --decode", "decode Morse back to text (default is encode)", action="store_true"),
    ],
    examples=[
        "aesop morse 'SOS'                     # -> ... --- ...",
        "aesop morse 'HELLO WORLD'",
        "aesop morse -d '... --- ...'          # -> SOS",
        "echo '.... . .-.. .-.. ---' | aesop morse -d",
    ],
    description="""
        International Morse code for letters, digits and common punctuation.
        Encoding joins letters with a space and words with '/'.  Decoding accepts
        that same shape (whitespace between letters, '/' between words).  Use -d
        to decode; the default direction is encode.
    """,
)
def cmd_morse(args, out) -> int:
    inp = io.load(args, encoding="raw")
    text = inp.text.strip("\n") if args.decode else inp.text
    out.raw(morse_decode(text) if args.decode else morse_encode(text))
    return 0


@command(
    "bacon",
    group="classical",
    summary="Encode or decode Bacon's 5-bit A/B cipher (24- or 26-letter)",
    manual="misc",
    aliases=["baconian"],
    args=io_args(positional="text", positional_help="text to encode (or A/B stream to decode)") + [
        arg("-d --decode", "decode an A/B stream back to text (default is encode)", action="store_true"),
        arg("--variant", "alphabet variant: 26 (distinct, lossless) or 24 (classic, I=J U=V)",
            choices=["24", "26"], default="26"),
    ],
    examples=[
        "aesop bacon 'HELLO'",
        "aesop bacon -d 'AABBB AABAA ABABB ABABB ABBBA'",
        "aesop bacon --variant 24 'JULIUS'",
        "echo '00010 00000 00010' | aesop bacon -d   # 0/1 accepted for A/B",
    ],
    description="""
        The Baconian cipher represents each letter as five binary symbols written
        as A/B.  The 26-letter variant (default) gives every letter its own code
        and round-trips losslessly; the classic 24-letter variant merges I with J
        and U with V, as Francis Bacon originally published it.  On decode, 0/1
        are accepted as aliases for A/B and all other characters are ignored.
    """,
)
def cmd_bacon(args, out) -> int:
    inp = io.load(args, encoding="raw")
    if args.decode:
        out.raw(bacon_decode(inp.text, variant=args.variant))
    else:
        out.raw(bacon_encode(inp.text, variant=args.variant))
    return 0


@command(
    "a1z26",
    group="classical",
    summary="Convert between letters and their alphabet numbers (A=1 … Z=26)",
    manual="misc",
    aliases=["a1z26cipher"],
    args=io_args(positional="text", positional_help="text to encode (or numbers to decode)") + [
        arg("-d --decode", "decode numbers back to letters (default is encode)", action="store_true"),
        arg("-s --sep", "separator between numbers on encode (default: space)", default=" "),
    ],
    examples=[
        "aesop a1z26 'HELLO'                   # -> 8 5 12 12 15",
        "aesop a1z26 -d '8 5 12 12 15'         # -> HELLO",
        "aesop a1z26 --sep - 'HELLO WORLD'     # -> 8-5-12-12-15 / 23-15-18-12-4",
        "echo '8 5 12 12 15' | aesop a1z26 -d",
    ],
    description="""
        A1Z26 replaces each letter by its position in the alphabet (A=1 … Z=26).
        Encoding joins the numbers in a word with --sep and separates words with
        '/'.  Decoding is separator-agnostic: it reads every run of digits, so
        any delimiter round-trips.  Numbers outside 1–26 are rejected.
    """,
)
def cmd_a1z26(args, out) -> int:
    inp = io.load(args, encoding="raw")
    if args.decode:
        try:
            out.raw(a1z26_decode(inp.text))
        except ValueError as exc:
            out.error(str(exc))
            return 1
    else:
        out.raw(a1z26_encode(inp.text, sep=args.sep))
    return 0


@command(
    "reverse",
    group="classical",
    summary="Reverse the input string character-for-character",
    manual="misc",
    aliases=["rev"],
    args=io_args(positional="text", positional_help="text to reverse"),
    examples=[
        "aesop reverse 'HELLO'                 # -> OLLEH",
        "aesop reverse 'nwad ta kcattA'",
        "echo 'reverse me' | aesop reverse",
    ],
    description="""
        Reverse the order of every character in the input — the trivial transform
        that hides inside many multi-layer puzzles (a base64 blob reversed, a
        flag written backwards).  Applying it twice returns the original.
    """,
)
def cmd_reverse(args, out) -> int:
    inp = io.load(args, encoding="raw")
    out.raw(reverse_text(inp.text))
    return 0

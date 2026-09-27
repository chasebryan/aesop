"""
Correctness tests for aesop.classical.misc — the fixed-alphabet grab-bag
(Atbash, ROT47, Morse, Bacon, A1Z26, Reverse).

These exercise the *cryptography*, not merely that the code runs:
  * involution / round-trip identities where the scheme is self-inverse,
  * encode->decode round-trips for the keyed-lookup schemes,
  * known-answer vectors from the literature / standards,
  * the classic-vs-modern Baconian variant semantics (I=J, U=V),
  * edge cases: case preservation, non-letters, empty input, padding,
    separator-agnostic decoding, out-of-range rejection,
  * one end-to-end pass through the real CLI.
"""
from __future__ import annotations

import string
import subprocess
import sys

import pytest

from aesop.classical.misc import (
    MORSE_CODE,
    MORSE_DECODE,
    a1z26_decode,
    a1z26_encode,
    atbash,
    bacon_decode,
    bacon_encode,
    morse_decode,
    morse_encode,
    reverse_text,
    rot47,
)

UPPER = string.ascii_uppercase
PRINTABLE_ASCII = "".join(chr(c) for c in range(33, 127))  # '!'..'~'


# --------------------------------------------------------------------------- #
# Atbash
# --------------------------------------------------------------------------- #
def test_atbash_known_vector():
    assert atbash("HELLO") == "SVOOL"
    assert atbash("SVOOL") == "HELLO"


def test_atbash_full_alphabet_is_reversal():
    assert atbash(UPPER) == UPPER[::-1]
    assert atbash(string.ascii_lowercase) == string.ascii_lowercase[::-1]


def test_atbash_formula_c_equals_25_minus_p():
    for i, ch in enumerate(UPPER):
        assert atbash(ch) == chr(ord("A") + (25 - i))


def test_atbash_is_involution():
    for s in ["HELLO", "Attack at dawn!", "MiXeD cAsE 123", ""]:
        assert atbash(atbash(s)) == s


def test_atbash_case_and_nonletters_preserved():
    src = "HeLLo, World! 42"
    out = atbash(src)
    for a, b in zip(src, out):
        if a.isupper():
            assert b.isupper()
        elif a.islower():
            assert b.islower()
        else:
            assert a == b  # non-letters untouched in place


# --------------------------------------------------------------------------- #
# ROT47
# --------------------------------------------------------------------------- #
def test_rot47_known_vector():
    assert rot47("Hello, World!") == "w6==@[ (@C=5P"


def test_rot47_is_involution_over_printable_range():
    assert rot47(rot47(PRINTABLE_ASCII)) == PRINTABLE_ASCII


def test_rot47_shifts_by_47():
    for ch in PRINTABLE_ASCII:
        expected = chr(33 + ((ord(ch) - 33 + 47) % 94))
        assert rot47(ch) == expected


def test_rot47_leaves_space_and_control_untouched():
    assert rot47(" ") == " "
    assert rot47("\t\n") == "\t\n"
    # embedded spaces preserved in position
    assert rot47("a b")[1] == " "


def test_rot47_empty():
    assert rot47("") == ""


# --------------------------------------------------------------------------- #
# Morse
# --------------------------------------------------------------------------- #
def test_morse_table_is_bijective():
    # a code table that silently dropped a collision would shrink here
    assert len(MORSE_DECODE) == len(MORSE_CODE)
    assert len(set(MORSE_CODE.values())) == len(MORSE_CODE)


def test_morse_known_vectors():
    assert morse_encode("SOS") == "... --- ..."
    assert morse_encode("HELLO WORLD") == ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
    # a handful of standard single-character codes
    assert morse_encode("E") == "."
    assert morse_encode("T") == "-"
    assert morse_encode("0") == "-----"
    assert morse_encode("9") == "----."


def test_morse_decode_known_vectors():
    assert morse_decode("... --- ...") == "SOS"
    assert morse_decode(".... . .-.. .-.. --- / .-- --- .-. .-.. -..") == "HELLO WORLD"


def test_morse_roundtrip_upcases():
    # encode ignores case; decode returns upper -> round-trip up to case
    for s in ["hello world", "Attack At Dawn", "the quick brown fox"]:
        assert morse_decode(morse_encode(s)) == s.upper()


def test_morse_roundtrip_with_digits_and_punctuation():
    s = "HELLO, WORLD 123!"
    assert morse_decode(morse_encode(s)) == s


def test_morse_decode_is_lenient_about_slash_spacing():
    assert morse_decode("...   ---   ...") == "SOS"  # extra intra spacing
    assert morse_decode("... --- .../... --- ...") == "SOS SOS"  # no spaces around slash
    assert morse_decode("  ... --- ...  ") == "SOS"  # surrounding whitespace


def test_morse_encode_skips_unmapped_chars():
    # a char with no Morse mapping (e.g. '#') is silently dropped
    assert morse_encode("A#B") == ".- -..."


def test_morse_empty():
    assert morse_encode("") == ""
    assert morse_decode("") == ""


# --------------------------------------------------------------------------- #
# Baconian
# --------------------------------------------------------------------------- #
def test_bacon26_known_vectors():
    assert bacon_encode("A") == "AAAAA"
    assert bacon_encode("B") == "AAAAB"
    assert bacon_encode("Z") == "BBAAB"
    assert bacon_encode("HELLO") == "AABBB AABAA ABABB ABABB ABBBA"


def test_bacon26_all_codes_distinct_and_5_bits():
    codes = bacon_encode(UPPER).split()
    assert len(codes) == 26
    assert all(len(c) == 5 and set(c) <= {"A", "B"} for c in codes)
    assert len(set(codes)) == 26  # lossless: every letter its own code


def test_bacon26_roundtrip_lossless():
    for s in ["HELLO", "THEQUICKBROWNFOX", "ATTACKATDAWN"]:
        assert bacon_decode(bacon_encode(s)) == s


def test_bacon26_roundtrip_multiword_and_evenlen():
    # even A/B length that would sniff as hex if not loaded raw; API is fine here
    s = "ATTACK AT DAWN"
    encoded = bacon_encode(s)
    # non-letters (spaces) are dropped on encode -> decode is contiguous letters
    assert bacon_decode(encoded) == s.replace(" ", "")


def test_bacon_decode_accepts_binary_aliases():
    # 0/1 accepted for A/B; 00111 00100 01011 01011 01110 == HELLO
    assert bacon_decode("00111 00100 01011 01011 01110") == "HELLO"
    # and the binary form matches the A/B form exactly
    assert bacon_decode("00111") == bacon_decode("AABBB")


def test_bacon_decode_ignores_cover_text():
    # spaces, punctuation and non-AB chars are stripped before grouping
    assert bacon_decode("aAbBb, AaBaA! aBaBb aBaBb aBbBa") == "HELLO"


def test_bacon_decode_drops_trailing_partial_group():
    # 10 usable bits + 3 dangling -> two letters, remainder discarded
    assert bacon_decode("AABBB AABAA AB") == "HE"


def test_bacon24_merges_i_j_and_u_v():
    # classic variant: I and J share a code, U and V share a code
    assert bacon_encode("I", variant="24") == bacon_encode("J", variant="24")
    assert bacon_encode("U", variant="24") == bacon_encode("V", variant="24")
    # decode resolves the shared code to the canonical member (I over J, U over V)
    assert bacon_decode(bacon_encode("J", variant="24"), variant="24") == "I"
    assert bacon_decode(bacon_encode("V", variant="24"), variant="24") == "U"


def test_bacon24_roundtrip_for_unmerged_letters():
    s = "HELLOWORLD"  # no I/J/U/V
    assert bacon_decode(bacon_encode(s, variant="24"), variant="24") == s


def test_bacon24_julius_is_lossy_as_documented():
    assert bacon_decode(bacon_encode("JULIUS", variant="24"), variant="24") == "IULIUS"


def test_bacon_unknown_variant_raises():
    with pytest.raises(ValueError):
        bacon_encode("HELLO", variant="99")


def test_bacon_empty():
    assert bacon_encode("") == ""
    assert bacon_decode("") == ""


# --------------------------------------------------------------------------- #
# A1Z26
# --------------------------------------------------------------------------- #
def test_a1z26_known_vectors():
    assert a1z26_encode("HELLO") == "8 5 12 12 15"
    assert a1z26_encode("HELLO WORLD") == "8 5 12 12 15 / 23 15 18 12 4"
    assert a1z26_decode("8 5 12 12 15") == "HELLO"
    assert a1z26_decode("8 5 12 12 15 / 23 15 18 12 4") == "HELLO WORLD"


def test_a1z26_full_alphabet():
    assert a1z26_encode(UPPER) == " ".join(str(i) for i in range(1, 27))
    assert a1z26_decode(" ".join(str(i) for i in range(1, 27))) == UPPER


def test_a1z26_roundtrip_default_sep():
    for s in ["HELLO WORLD", "ATTACK AT DAWN", "THE QUICK BROWN FOX"]:
        assert a1z26_decode(a1z26_encode(s)) == s


def test_a1z26_roundtrip_custom_separators():
    # decode is separator-agnostic: any inter-number delimiter round-trips
    for sep in ["-", ",", ".", "  ", "|"]:
        enc = a1z26_encode("HELLO WORLD", sep=sep)
        assert a1z26_decode(enc) == "HELLO WORLD"


def test_a1z26_decode_rejects_out_of_range():
    for bad in ["0", "27", "100", "8 5 27"]:
        with pytest.raises(ValueError):
            a1z26_decode(bad)


def test_a1z26_encode_skips_non_letters():
    assert a1z26_encode("A1B2C3") == "1 2 3"


def test_a1z26_empty():
    assert a1z26_encode("") == ""
    assert a1z26_decode("") == ""


# --------------------------------------------------------------------------- #
# Reverse
# --------------------------------------------------------------------------- #
def test_reverse_known_vector():
    assert reverse_text("HELLO") == "OLLEH"


def test_reverse_is_involution():
    for s in ["HELLO", "Attack at dawn", "12345!@#", ""]:
        assert reverse_text(reverse_text(s)) == s


def test_reverse_preserves_length_and_multiset():
    s = "The quick brown fox"
    r = reverse_text(s)
    assert len(r) == len(s)
    assert sorted(r) == sorted(s)


# --------------------------------------------------------------------------- #
# Cross-scheme: chaining layers (as a multi-stage puzzle would)
# --------------------------------------------------------------------------- #
def test_chain_atbash_then_reverse_roundtrips():
    s = "SECRETMESSAGE"
    stego = reverse_text(atbash(s))
    assert atbash(reverse_text(stego)) == s


# --------------------------------------------------------------------------- #
# End-to-end: the real CLI dispatch path
# --------------------------------------------------------------------------- #
def _cli(*argv, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "aesop", *argv],
        input=stdin,
        capture_output=True,
        text=True,
    )


def test_cli_atbash_roundtrip():
    r = _cli("atbash", "HELLO")
    assert r.returncode == 0
    assert r.stdout.strip() == "SVOOL"


def test_cli_a1z26_decode_numeric_stdin_not_treated_as_hex():
    # regression: '8 5 12 12 15' is valid hex; must be read as literal A1Z26
    r = _cli("a1z26", "-d", stdin="8 5 12 12 15\n")
    assert r.returncode == 0
    assert r.stdout.strip() == "HELLO"


def test_cli_a1z26_decode_out_of_range_errors():
    r = _cli("a1z26", "-d", "99")
    assert r.returncode == 1


def test_cli_bacon_roundtrip():
    enc = _cli("bacon", "HELLO").stdout.strip()
    assert enc == "AABBB AABAA ABABB ABABB ABBBA"
    dec = _cli("bacon", "-d", enc)
    assert dec.stdout.strip() == "HELLO"

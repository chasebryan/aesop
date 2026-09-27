"""
Correctness tests for aesop.classical.affine — the Affine cipher.

These exercise the *cryptography*, not just that the code runs:
  * round-trip identity (decrypt(encrypt(x)) == x) over the whole legal keyspace,
  * known-answer / textbook vectors from the literature,
  * that the solvers actually recover a known key + plaintext,
  * the mathematical constraints (coprime multipliers, invertibility),
  * edge cases: case preservation, non-letters, empty input, wrap-around.
"""
from __future__ import annotations

import math
import string

import pytest

from aesop.classical.affine import (
    COPRIME_WITH_26,
    best_by_chi2,
    brute_force,
    decrypt,
    encrypt,
    solve,
)

M = 26

# A paragraph of ordinary English — enough letters for quadgram scoring to lock
# the true key at rank 1.
PLAINTEXT = (
    "The quick brown fox jumps over the lazy dog. "
    "Attack at dawn, the fox is watching the crow. "
    "We hold these truths to be self evident."
)


# --------------------------------------------------------------------------- #
# Key-space invariants
# --------------------------------------------------------------------------- #
def test_coprime_set_is_exact():
    """Exactly the 12 residues coprime with 26, in order."""
    assert COPRIME_WITH_26 == [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    assert len(COPRIME_WITH_26) == 12
    for a in COPRIME_WITH_26:
        assert math.gcd(a, M) == 1
    # nothing legal is missing
    assert [a for a in range(M) if math.gcd(a, M) == 1] == COPRIME_WITH_26


def test_illegal_multipliers_rejected():
    """Multipliers sharing a factor with 26 must raise on encrypt and decrypt."""
    for a in (0, 2, 13, 26):  # even, the factor 13, and 0/26 ≡ 0
        with pytest.raises(ValueError):
            encrypt("hello", a, 3)
        with pytest.raises(ValueError):
            decrypt("hello", a, 3)


# --------------------------------------------------------------------------- #
# Known-answer tests (literature vectors)
# --------------------------------------------------------------------------- #
def test_textbook_vector_wikipedia():
    """Wikipedia's canonical affine example: a=5, b=8."""
    assert encrypt("Attack at dawn", 5, 8) == "Izzisg iz xiov"
    assert decrypt("Izzisg iz xiov", 5, 8) == "Attack at dawn"


def test_caesar_is_special_case_a1():
    """a=1 collapses to a pure Caesar shift of b."""
    # ROT: 'A'->'D' with b=3
    assert encrypt("ABC", 1, 3) == "DEF"
    assert encrypt("xyz", 1, 3) == "abc"  # wrap-around, lowercase preserved


def test_atbash_is_special_case_a25_b25():
    """a=25, b=25 is Atbash (the alphabet reversed): A<->Z, B<->Y, ..."""
    assert encrypt(string.ascii_uppercase, 25, 25) == string.ascii_uppercase[::-1]
    # Atbash is its own inverse
    assert encrypt(encrypt("hello world", 25, 25), 25, 25) == "hello world"


def test_full_alphabet_mapping_a5_b8():
    """Spell out the whole permutation for a=5,b=8 and check each letter."""
    expected = "".join(chr((5 * i + 8) % 26 + ord("A")) for i in range(26))
    assert encrypt(string.ascii_uppercase, 5, 8) == expected
    # and that it is a genuine permutation (bijective) — no collisions
    assert sorted(expected) == list(string.ascii_uppercase)


# --------------------------------------------------------------------------- #
# Round-trip property over the entire keyspace
# --------------------------------------------------------------------------- #
def test_roundtrip_all_keys():
    """decrypt(encrypt(msg,a,b),a,b) == msg for every legal (a,b)."""
    msg = "The Quick Brown Fox, jumps! over 123 the lazy DOG."
    for a in COPRIME_WITH_26:
        for b in range(M):
            ct = encrypt(msg, a, b)
            assert decrypt(ct, a, b) == msg, f"round-trip failed for a={a}, b={b}"


def test_encryption_is_bijective_on_letters():
    """For every legal key, the 26 letters map to 26 distinct letters."""
    for a in COPRIME_WITH_26:
        for b in range(M):
            mapped = encrypt(string.ascii_uppercase, a, b)
            assert sorted(mapped) == list(string.ascii_uppercase), (a, b)


def test_b_reduced_mod_26():
    """b outside 0-25 is reduced modulo 26 (b and b+26 agree)."""
    assert encrypt("hello", 5, 8) == encrypt("hello", 5, 8 + 26)
    assert encrypt("hello", 5, 8) == encrypt("hello", 5, -18)  # -18 ≡ 8


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #
def test_case_preserved():
    ct = encrypt("HeLLo", 7, 4)
    # upper stays upper, lower stays lower
    assert ct[0].isupper() and ct[1].islower()
    assert decrypt(ct, 7, 4) == "HeLLo"


def test_non_letters_pass_through():
    src = "12:34, foo-bar! ~"
    ct = encrypt(src, 9, 11)
    # every non-letter is untouched, in place
    for a_ch, b_ch in zip(src, ct):
        if not a_ch.isalpha():
            assert a_ch == b_ch
    assert decrypt(ct, 9, 11) == src


def test_empty_and_digits_only():
    assert encrypt("", 5, 8) == ""
    assert decrypt("", 5, 8) == ""
    assert encrypt("12345", 5, 8) == "12345"


# --------------------------------------------------------------------------- #
# Solvers actually recover the key/plaintext
# --------------------------------------------------------------------------- #
def test_brute_force_covers_full_keyspace():
    results = brute_force("Izzisg iz xiov")
    assert len(results) == len(COPRIME_WITH_26) * M  # 312
    keys = {k for k, _, _ in results}
    assert len(keys) == 312  # every key distinct
    # the true key must appear and yield the true plaintext
    hits = [pt for k, pt, _ in results if k == (5, 8)]
    assert hits == ["Attack at dawn"]


def test_brute_force_contains_true_plaintext():
    ct = encrypt(PLAINTEXT, 11, 20)
    plaintexts = {pt for _, pt, _ in brute_force(ct)}
    assert PLAINTEXT in plaintexts


@pytest.mark.parametrize("a,b", [(5, 8), (7, 3), (11, 20), (25, 25), (3, 0)])
def test_solve_recovers_key_and_plaintext(a, b):
    """On real English, quadgram solve floats the true (a,b) to rank 1."""
    ct = encrypt(PLAINTEXT, a, b)
    ranked = solve(ct, top=3)
    (best_a, best_b), best_pt, _ = ranked[0]
    assert (best_a, best_b) == (a, b), f"top candidate was ({best_a},{best_b})"
    assert best_pt == PLAINTEXT


def test_solve_top_count_respected():
    ct = encrypt(PLAINTEXT, 5, 8)
    assert len(solve(ct, top=5)) == 5
    assert len(solve(ct, top=1)) == 1
    # top<1 is clamped to at least 1 (never empty / crash)
    assert len(solve(ct, top=0)) == 1


def test_chi2_recovers_key_on_ample_text():
    """chi-squared frequency match recovers the key given enough letters."""
    ct = encrypt(PLAINTEXT, 7, 3)
    assert best_by_chi2(ct) == (7, 3)

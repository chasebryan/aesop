"""
Correctness tests for aesop.classical.vigenere — the Vigenère cipher.

These exercise the *cryptography*, not merely that the code runs:
  * round-trip identity (decrypt(encrypt(x)) == x) over many keys,
  * known-answer / textbook vectors from the literature (ATTACKATDAWN / LEMON),
  * the "key advances only on letters" convention and case/layout preservation,
  * key-length detection (Friedman IC + Kasiski) surfacing the true period,
  * that recover_key / solve_with_length / solve actually recover a known
    key + plaintext on constructed cases,
  * edge cases: empty key, empty text, digits-only, key normalisation,
    repeated-key collapse to the fundamental period.
"""
from __future__ import annotations

import string

import pytest

from aesop.classical.vigenere import (
    _clean_key,
    _minimal_period,
    decrypt,
    encrypt,
    guess_key_lengths,
    kasiski,
    recover_key,
    solve,
    solve_with_length,
)

# A paragraph of ordinary English — enough letters for quadgram scoring to lock
# the true key at rank 1, but small enough to keep the solve fast.
PROSE = (
    "We hold these truths to be self evident that all men are created equal "
    "endowed by their creator with certain unalienable rights among these are "
    "life liberty and the pursuit of happiness."
)


# --------------------------------------------------------------------------- #
# Known-answer tests (literature vectors)
# --------------------------------------------------------------------------- #
def test_canonical_lemon_vector():
    """The textbook Vigenère example: ATTACKATDAWN under LEMON -> LXFOPVEFRNHR."""
    assert encrypt("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    assert decrypt("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN"


def test_encrypt_matches_manual_formula():
    """c = (p + k) mod 26, letter by letter, against an independent computation."""
    pt = "THEQUICKBROWNFOX"
    key = "SECRET"
    shifts = [ord(c) - ord("A") for c in key]
    expected = "".join(
        chr((ord(ch) - ord("A") + shifts[i % len(shifts)]) % 26 + ord("A"))
        for i, ch in enumerate(pt)
    )
    assert encrypt(pt, key) == expected


def test_single_letter_key_is_caesar():
    """A one-letter key degenerates to a pure Caesar shift."""
    # key 'B' -> shift of 1
    assert encrypt("ABCXYZ", "B") == "BCDYZA"
    # key 'A' -> shift of 0 -> identity
    assert encrypt("Hello, World!", "A") == "Hello, World!"


# --------------------------------------------------------------------------- #
# Round-trip properties
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "key", ["A", "B", "LEMON", "zeus", "Secret", "CRYPTANALYSIS", "z"]
)
def test_roundtrip_identity(key):
    """decrypt(encrypt(msg, key), key) == msg, preserving case & punctuation."""
    msg = "The Quick Brown Fox, jumps! over 123 the LAZY dog."
    ct = encrypt(msg, key)
    assert decrypt(ct, key) == msg


def test_roundtrip_over_alphabet_for_every_shift():
    """Every single-letter key round-trips the whole alphabet exactly."""
    for c in string.ascii_uppercase:
        ct = encrypt(string.ascii_uppercase, c)
        assert decrypt(ct, c) == string.ascii_uppercase
        assert sorted(ct) == list(string.ascii_uppercase)  # a permutation


# --------------------------------------------------------------------------- #
# Case, layout and key-normalisation conventions
# --------------------------------------------------------------------------- #
def test_case_preserved():
    ct = encrypt("HeLLo", "KEY")
    assert ct[0].isupper() and ct[1].islower()
    assert decrypt(ct, "KEY") == "HeLLo"


def test_key_advances_only_on_letters():
    """The 'skip punctuation' convention: the key does not advance on non-letters.

    'AB CD' under key 'BC' shifts A by B(=1), B by C(=2), then — the space
    consuming no key letter — C by B(=1) and D by C(=2): 'BD DF'.
    """
    assert encrypt("AB CD", "BC") == "BD DF"
    # Equivalent check: inserting non-letters must not shift the letter mapping.
    plain = "ATTACKATDAWN"
    spaced = "AT TACK, AT-DAWN"
    ce = encrypt(plain, "LEMON")
    cs = encrypt(spaced, "LEMON")
    assert [c for c in cs if c.isalpha()] == list(ce)


def test_key_is_case_and_nonletter_insensitive():
    """Key normalisation: case and non-letters in the key are ignored."""
    assert _clean_key("l e m o n") == "LEMON"
    assert _clean_key("LeMoN!") == "LEMON"
    assert encrypt("hello world", "LEMON") == encrypt("hello world", "l-e-m-o-n")


def test_empty_key_raises():
    """A key with no letters is an error, not a silent no-op."""
    with pytest.raises(ValueError):
        encrypt("hello", "")
    with pytest.raises(ValueError):
        encrypt("hello", "12345")
    with pytest.raises(ValueError):
        decrypt("hello", "!!!")


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #
def test_non_letters_pass_through():
    src = "12:34, foo-bar! ~"
    ct = encrypt(src, "KEY")
    for a_ch, b_ch in zip(src, ct):
        if not a_ch.isalpha():
            assert a_ch == b_ch
    assert decrypt(ct, "KEY") == src


def test_digits_only_unchanged():
    assert encrypt("12345", "LEMON") == "12345"
    assert decrypt("12345", "LEMON") == "12345"


def test_minimal_period_collapses_repeats():
    assert _minimal_period("LEMONLEMON") == "LEMON"
    assert _minimal_period("ABAB") == "AB"
    assert _minimal_period("AAAA") == "A"
    assert _minimal_period("LEMON") == "LEMON"  # already minimal
    assert _minimal_period("ABCAB") == "ABCAB"  # not a clean repeat


# --------------------------------------------------------------------------- #
# Key-length detection
# --------------------------------------------------------------------------- #
def test_guess_key_lengths_surfaces_true_period():
    """Friedman IC: the top-ranked lengths are all multiples of the true period.

    A wrong length scrambles columns toward IC 0.0385; the true length and its
    multiples keep each column monoalphabetic (IC near English's 0.0667).
    """
    long_prose = (PROSE + " ") * 3
    ct = encrypt(long_prose, "ZEUS")  # period 4
    top = [L for L, _ic in guess_key_lengths(ct)[:4]]
    assert all(L % 4 == 0 for L in top), top
    # and the true period itself is among the leaders
    assert 4 in top


def test_kasiski_votes_for_true_period():
    """Kasiski divisor votes include the true key length among the leaders."""
    long_prose = (PROSE + " ") * 4
    ct = encrypt(long_prose, "LEMON")  # period 5
    votes = dict(kasiski(ct))
    assert 5 in votes and votes[5] > 0
    # 5 should be one of the better-supported divisors
    ranked = [f for f, _v in kasiski(ct)]
    assert 5 in ranked[:6]


# --------------------------------------------------------------------------- #
# Key recovery on a known case
# --------------------------------------------------------------------------- #
def test_recover_key_on_ample_text():
    """chi-squared per column recovers the exact key given enough letters."""
    long_prose = (PROSE + " ") * 3
    ct = encrypt(long_prose, "ZEUS")
    assert recover_key(ct, 4) == "ZEUS"


def test_recover_key_rejects_bad_length():
    with pytest.raises(ValueError):
        recover_key("ANYTHING", 0)


@pytest.mark.parametrize("key", ["ZEUS", "FOX", "THUNDER"])
def test_solve_with_length_recovers_key(key):
    """Given the correct length, solve_with_length returns the true key + plaintext."""
    ct = encrypt(PROSE, key)
    rec_key, plain = solve_with_length(ct, len(key))
    assert rec_key == key
    assert plain == PROSE


# --------------------------------------------------------------------------- #
# Full auto-solve (no key, no length supplied)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("key", ["ZEUS", "THUNDER", "CRYPTANALYSIS"])
def test_solve_auto_recovers_key_and_plaintext(key):
    ct = encrypt(PROSE, key)
    rec_key, plain, _score = solve(ct)
    assert rec_key == key, f"recovered {rec_key!r}, expected {key!r}"
    assert plain == PROSE


def test_solve_spec_vector_48_letters():
    """The required spec case: recover LEMON + exact plaintext from short text."""
    spec = "the quick brown fox jumps over the lazy dog many times over"
    ct = encrypt(spec, "lemon")
    rec_key, plain, _score = solve(ct)
    assert rec_key == "LEMON"
    assert plain == spec


def test_solve_is_deterministic():
    """A fixed RNG seed makes solve repeatable across runs."""
    ct = encrypt(PROSE, "ZEUS")
    assert solve(ct) == solve(ct)


def test_solve_short_input_returns_gracefully():
    """Sub-two-letter input hits the guard and is returned unchanged, not crashed."""
    key, plain, _score = solve("H")
    assert key == "" and plain == "H"
    # A couple of letters is still too little to break, but must not raise.
    k2, p2, _ = solve("Hi")
    assert isinstance(k2, str) and isinstance(p2, str)

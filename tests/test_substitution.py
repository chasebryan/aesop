"""
Correctness tests for aesop.classical.substitution — the general
monoalphabetic substitution cipher.

These exercise the *cryptography*, not merely that the code runs:
  * round-trip identity (decrypt(encrypt(x, k), k) == x) over many random keys,
  * known-answer / textbook vectors (QWERTY-keyboard key, Atbash, Caesar),
  * key-space invariants (normalize/invert are genuine bijections),
  * that the solver actually recovers a known plaintext + key on a constructed
    English cryptogram,
  * edge cases: case preservation, non-letters passing through, empty/short input.

The solver tests use small restart/iteration counts so the whole file runs in
a few seconds.
"""
from __future__ import annotations

import random
import string

import pytest

from aesop.classical.substitution import (
    ALPHABET,
    apply_key,
    decrypt,
    invert_key,
    normalize_key,
    solve,
)
from aesop.core.score import clean_text

# A QWERTY-keyboard permutation used throughout (also the module's headline
# example key).
QWERTY = "QWERTYUIOPASDFGHJKLZXCVBNM"

# A paragraph of ordinary English, > 200 letters — enough for quadgram scoring
# to lock the true key.
PLAINTEXT = (
    "The quick brown fox jumps over the lazy dog. "
    "Attack at dawn, the fox is watching the crow while the hounds sleep. "
    "We hold these truths to be self evident, that all men are created equal, "
    "endowed with certain unalienable rights among which are life and liberty. "
    "Frequency analysis reveals the habit hiding behind every masked letter."
)


def _accuracy(recovered: str, truth: str) -> float:
    """Fraction of matching letters (alphabetic only) between two texts."""
    a, b = clean_text(recovered), clean_text(truth)
    if not b:
        return 1.0
    return sum(1 for x, y in zip(a, b) if x == y) / len(b)


# --------------------------------------------------------------------------- #
# Key validation / normalization
# --------------------------------------------------------------------------- #
def test_normalize_uppercases_and_strips_whitespace():
    assert normalize_key(QWERTY.lower()) == QWERTY
    assert normalize_key("QWERTYUIOP ASDFGHJKL ZXCVBNM") == QWERTY
    assert normalize_key("  " + QWERTY + "\n") == QWERTY


def test_normalize_accepts_identity_and_reverse():
    assert normalize_key(ALPHABET) == ALPHABET
    assert normalize_key(ALPHABET[::-1]) == ALPHABET[::-1]


@pytest.mark.parametrize(
    "bad",
    [
        "ABC",                              # too short
        "A" * 26,                          # right length, not a permutation
        ALPHABET[:-1] + "A",               # 26 letters, duplicate A, missing Z
        ALPHABET + "A",                    # too long
        "QWERTYUIOPASDFGHJKLZXCVBN1",      # contains a digit
        "",                                # empty
    ],
)
def test_normalize_rejects_non_permutations(bad):
    with pytest.raises(ValueError):
        normalize_key(bad)


# --------------------------------------------------------------------------- #
# invert_key is a true inverse permutation
# --------------------------------------------------------------------------- #
def test_invert_is_involution():
    rng = random.Random(7)
    for _ in range(50):
        key = list(ALPHABET)
        rng.shuffle(key)
        key = "".join(key)
        assert invert_key(invert_key(key)) == key


def test_invert_composes_to_identity():
    """Applying key then its inverse (and vice versa) is the identity map."""
    rng = random.Random(11)
    for _ in range(20):
        key = list(ALPHABET)
        rng.shuffle(key)
        key = "".join(key)
        inv = invert_key(key)
        # For every letter, key then inv returns the original.
        assert apply_key(apply_key(ALPHABET, key), inv) == ALPHABET
        assert apply_key(apply_key(ALPHABET, inv), key) == ALPHABET


def test_apply_key_is_bijective_on_the_alphabet():
    """Any valid key maps the 26 letters onto 26 distinct letters."""
    rng = random.Random(3)
    for _ in range(20):
        key = list(ALPHABET)
        rng.shuffle(key)
        key = "".join(key)
        mapped = apply_key(ALPHABET, key)
        assert sorted(mapped) == list(ALPHABET)
        assert mapped == key  # A->key[0], ..., Z->key[25]


# --------------------------------------------------------------------------- #
# Known-answer / textbook vectors
# --------------------------------------------------------------------------- #
def test_qwerty_key_vector():
    """The module's own headline vector."""
    assert apply_key("Attack at dawn", QWERTY) == "Qzzqea qz rqvf"
    assert decrypt("Qzzqea qz rqvf", QWERTY) == "Attack at dawn"


def test_atbash_as_substitution():
    """The reversed alphabet is Atbash: A<->Z, and it is its own inverse."""
    atbash = ALPHABET[::-1]
    assert apply_key(string.ascii_uppercase, atbash) == string.ascii_uppercase[::-1]
    assert invert_key(atbash) == atbash  # self-inverse
    assert apply_key(apply_key("hello world", atbash), atbash) == "hello world"


def test_caesar_as_substitution():
    """A rotated alphabet reproduces a Caesar shift (here ROT3)."""
    rot3 = ALPHABET[3:] + ALPHABET[:3]  # A->D, B->E, ...
    assert apply_key("ABC", rot3) == "DEF"
    assert apply_key("xyz", rot3) == "abc"  # wrap-around, lowercase preserved
    assert decrypt("DEF", rot3) == "ABC"


def test_identity_key_is_a_noop():
    assert apply_key("Hello, World! 123", ALPHABET) == "Hello, World! 123"
    assert decrypt("Hello, World! 123", ALPHABET) == "Hello, World! 123"


# --------------------------------------------------------------------------- #
# Round-trip property over many random keys
# --------------------------------------------------------------------------- #
def test_roundtrip_many_keys():
    msg = "The Quick Brown Fox, jumps! over 123 the LAZY dog. ~@#"
    rng = random.Random(42)
    for _ in range(200):
        key = list(ALPHABET)
        rng.shuffle(key)
        key = "".join(key)
        ct = apply_key(msg, key)
        assert decrypt(ct, key) == msg
        # encrypt(decrypt(x)) also round-trips
        assert apply_key(decrypt(msg, key), key) == msg


def test_decrypt_is_encrypt_with_inverse_key():
    rng = random.Random(99)
    msg = "Meet me at midnight by the old oak tree."
    for _ in range(20):
        key = list(ALPHABET)
        rng.shuffle(key)
        key = "".join(key)
        assert decrypt(msg, key) == apply_key(msg, invert_key(key))


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #
def test_case_preserved():
    ct = apply_key("HeLLo", QWERTY)
    assert ct[0].isupper() and ct[1].islower()
    assert ct[2].isupper() and ct[3].isupper() and ct[4].islower()
    assert decrypt(ct, QWERTY) == "HeLLo"


def test_non_letters_pass_through_in_place():
    src = "12:34, foo-bar! ~\tnewline\n"
    ct = apply_key(src, QWERTY)
    assert len(ct) == len(src)
    for a_ch, b_ch in zip(src, ct):
        if not a_ch.isalpha():
            assert a_ch == b_ch
    assert decrypt(ct, QWERTY) == src


def test_empty_and_digit_only():
    assert apply_key("", QWERTY) == ""
    assert decrypt("", QWERTY) == ""
    assert apply_key("12345", QWERTY) == "12345"


# --------------------------------------------------------------------------- #
# The solver actually recovers key + plaintext
# --------------------------------------------------------------------------- #
def test_solve_recovers_known_plaintext():
    """Encrypt a known paragraph with a random key; the solver recovers it."""
    rng = random.Random(2024)
    key = list(ALPHABET)
    rng.shuffle(key)
    key = "".join(key)
    ct = apply_key(PLAINTEXT, key)

    enc_key, plaintext, score = solve(ct, restarts=12, iterations=4000)

    # Near-perfect letter recovery on 200+ letters.
    assert _accuracy(plaintext, PLAINTEXT) >= 0.95
    # The reported key is a genuine encryption key that round-trips the result.
    assert normalize_key(enc_key) == enc_key
    assert decrypt(ct, enc_key) == plaintext


def test_solve_result_is_self_consistent():
    """decrypt(ct, recovered_key) must reproduce the returned plaintext exactly,
    regardless of how good the recovery is."""
    rng = random.Random(5)
    key = list(ALPHABET)
    rng.shuffle(key)
    key = "".join(key)
    ct = apply_key(PLAINTEXT, key)
    enc_key, plaintext, _ = solve(ct, restarts=6, iterations=3000)
    assert decrypt(ct, enc_key) == plaintext
    assert apply_key(plaintext, enc_key) == ct or _accuracy(plaintext, PLAINTEXT) < 1.0


def test_solve_is_deterministic():
    """Same ciphertext + same parameters -> identical result (seeded RNG)."""
    ct = apply_key(PLAINTEXT, QWERTY)
    r1 = solve(ct, restarts=6, iterations=3000, seed=0)
    r2 = solve(ct, restarts=6, iterations=3000, seed=0)
    assert r1 == r2


def test_solve_short_input_returns_identity():
    """Below the 4-letter floor, solve returns the identity key gracefully."""
    key, plaintext, _ = solve("HI")
    assert key == ALPHABET
    assert plaintext == "HI"
    key, plaintext, _ = solve("")
    assert key == ALPHABET
    assert plaintext == ""

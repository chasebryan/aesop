"""
Correctness tests for aesop.classical.transposition.

These check that the *crypto is right*, not merely that it runs:
  * round-trip identity for rail-fence and columnar (many rails/keys/lengths),
  * known-answer vectors from the classical literature (the canonical
    WEAREDISCOVEREDFLEEATONCE example, both schemes),
  * that the brute-force solvers recover a known plaintext/key at rank 1 on a
    realistic-length message,
  * the order<->digit-key bijection,
  * edge cases: empty input, tiny input, interior-space preservation,
    lowercase preservation, and key-validation error paths.
"""
from __future__ import annotations

import itertools
import random
import string

import pytest

from aesop.classical.transposition import (
    railfence_encrypt,
    railfence_decrypt,
    solve_railfence,
    columnar_encrypt,
    columnar_decrypt,
    solve_columnar,
    parse_key,
    _order_to_key,
)


# --------------------------------------------------------------------------- #
# Known-answer tests (canonical textbook vectors)
# --------------------------------------------------------------------------- #
PLAIN = "WEAREDISCOVEREDFLEEATONCE"
RAIL3_CT = "WECRLTEERDSOEEFEAOCAIVDEN"
COL_ZEBRA_CT = "EODAEASRENEIELORCEECWDVFT"


def test_kat_railfence_3_encrypt():
    assert railfence_encrypt(PLAIN, 3) == RAIL3_CT


def test_kat_railfence_3_decrypt():
    assert railfence_decrypt(RAIL3_CT, 3) == PLAIN


def test_kat_columnar_zebra_encrypt():
    assert columnar_encrypt(PLAIN, "ZEBRA") == COL_ZEBRA_CT


def test_kat_columnar_zebra_decrypt():
    assert columnar_decrypt(COL_ZEBRA_CT, "ZEBRA") == PLAIN


def test_kat_columnar_zebra_readorder_key():
    """ZEBRA's read order is columns 5,3,2,4,1 -> digit key 53241; must agree."""
    assert columnar_encrypt(PLAIN, "53241") == COL_ZEBRA_CT
    assert columnar_decrypt(COL_ZEBRA_CT, "53241") == PLAIN


# --------------------------------------------------------------------------- #
# Round-trip (encrypt -> decrypt == identity)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("rails", list(range(2, 12)))
@pytest.mark.parametrize("length", [1, 2, 3, 5, 13, 40, 41, 100])
def test_railfence_roundtrip(rails, length):
    rng = random.Random(f"rail-{rails}-{length}")
    txt = "".join(rng.choice(string.ascii_uppercase) for _ in range(length))
    ct = railfence_encrypt(txt, rails)
    assert len(ct) == len(txt)  # transposition preserves length
    assert railfence_decrypt(ct, rails) == txt


@pytest.mark.parametrize(
    "key",
    ["ZEBRA", "GERMAN", "LEMON", "SECRET", "31542", "3 1 5 4 2", "3,1,5,4,2", "CRYPTOGRAPHY"],
)
@pytest.mark.parametrize("length", [2, 5, 10, 17, 23, 24, 25, 26, 31])
def test_columnar_roundtrip(key, length):
    rng = random.Random(f"col-{key}-{length}")
    txt = "".join(rng.choice(string.ascii_uppercase) for _ in range(length))
    ct = columnar_encrypt(txt, key)
    assert len(ct) == len(txt)  # transposition preserves length
    assert columnar_decrypt(ct, key) == txt


def test_railfence_is_a_permutation():
    """Ciphertext must be an anagram of the plaintext (letters kept, order moved)."""
    ct = railfence_encrypt(PLAIN, 5)
    assert sorted(ct) == sorted(PLAIN)


def test_columnar_is_a_permutation():
    ct = columnar_encrypt(PLAIN, "GERMAN")
    assert sorted(ct) == sorted(PLAIN)


# --------------------------------------------------------------------------- #
# order <-> digit-key bijection
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cols", [2, 3, 4, 5, 6])
def test_order_key_bijection(cols):
    for perm in itertools.permutations(range(cols)):
        key = _order_to_key(perm)
        assert list(parse_key(key)) == list(perm)


def test_parse_key_keyword_and_digits_agree():
    """A keyword and its equivalent digit permutation must resolve identically."""
    assert parse_key("ZEBRA") == parse_key("53241")


# --------------------------------------------------------------------------- #
# Solvers recover the truth
# --------------------------------------------------------------------------- #
# Realistic-length English so quadgram scoring floats the plaintext to rank 1.
SOLVE_PT = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDESCAPESINTOTHEFOREST"


def test_solve_railfence_recovers_rank1():
    ct = railfence_encrypt(SOLVE_PT, 4)
    results = solve_railfence(ct, max_rails=15, top=3)
    rails, pt, _score = results[0]
    assert pt == SOLVE_PT
    assert rails == 4


def test_solve_columnar_recovers_rank1():
    key = "53241"
    ct = columnar_encrypt(SOLVE_PT, key)
    results = solve_columnar(ct, max_cols=8, top=3)
    rkey, cols, pt, _score = results[0]
    assert pt == SOLVE_PT
    assert cols == 5
    # The reported key must actually decrypt the ciphertext back to the plaintext.
    assert columnar_decrypt(ct, rkey) == SOLVE_PT


def test_solve_columnar_true_key_in_pool():
    """Even when not rank 1, the true reading must be reachable & decrypt right."""
    key = "53241"
    ct = columnar_encrypt(SOLVE_PT, key)
    results = solve_columnar(ct, max_cols=8, top=100)
    assert any(pt == SOLVE_PT and columnar_decrypt(ct, k) == SOLVE_PT
               for k, _c, pt, _s in results)


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #
def test_empty_input():
    assert railfence_encrypt("", 3) == ""
    assert railfence_decrypt("", 3) == ""
    assert columnar_encrypt("", "ZEBRA") == ""
    assert columnar_decrypt("", "ZEBRA") == ""


def test_tiny_input_railfence_identity():
    # length <= rails is a genuine no-op for the zig-zag (each char on its own rail)
    assert railfence_encrypt("AB", 3) == "AB"
    assert railfence_decrypt("AB", 3) == "AB"


def test_interior_spaces_preserved_railfence():
    txt = "WE ARE HERE NOW"
    assert railfence_decrypt(railfence_encrypt(txt, 4), 4) == txt


def test_interior_spaces_preserved_columnar():
    txt = "WE ARE HERE NOW"
    assert columnar_decrypt(columnar_encrypt(txt, "ZEBRA"), "ZEBRA") == txt


def test_case_preserved():
    txt = "weArEdIscovered"
    assert railfence_decrypt(railfence_encrypt(txt, 3), 3) == txt
    assert columnar_decrypt(columnar_encrypt(txt, "ZEBRA"), "ZEBRA") == txt


def test_nonletters_preserved_and_permuted():
    txt = "ATTACK-AT-DAWN!! 123"
    ct = railfence_encrypt(txt, 4)
    assert sorted(ct) == sorted(txt)          # every char kept
    assert railfence_decrypt(ct, 4) == txt    # and restorable


def test_irregular_grid_last_row():
    """23 chars over 5 columns -> a ragged final row must still round-trip."""
    txt = "".join(random.Random("ragged").choice(string.ascii_uppercase) for _ in range(23))
    assert len(txt) % 5 != 0
    assert columnar_decrypt(columnar_encrypt(txt, "ZEBRA"), "ZEBRA") == txt


# --------------------------------------------------------------------------- #
# Key validation error paths
# --------------------------------------------------------------------------- #
def test_parse_key_rejects_empty():
    with pytest.raises(ValueError):
        parse_key("")


def test_parse_key_rejects_single_column():
    with pytest.raises(ValueError):
        parse_key("A")


def test_parse_key_rejects_repeated_digits():
    with pytest.raises(ValueError):
        parse_key("112")
    with pytest.raises(ValueError):
        parse_key("3 3")


def test_parse_key_keyword_with_repeated_letters_ok():
    """Keyword repeats are legal (ties broken left-to-right) and round-trip."""
    order = parse_key("SECRET")
    assert sorted(order) == list(range(6))  # still a valid permutation
    txt = "MEETMEATNOONTOMORROW"
    assert columnar_decrypt(columnar_encrypt(txt, "SECRET"), "SECRET") == txt

"""
Correctness tests for aesop.classical.playfair — the Playfair digraph cipher.

These exercise the *cryptography*, not merely that the code runs:
  * key-square construction (keyword dedup, J->I fold, alphabet fill),
  * textbook known-answer vectors from the literature
    (PLAYFAIR EXAMPLE / "Hide the gold..." and MONARCHY / INSTRUMENTS),
  * round-trip identity decrypt(encrypt(p, k), k) == prepared_plaintext(p),
  * the structural invariants (never emits a doubled digraph, output length
    even, J absent, digraph rules incl. same-row/col wrap and rectangle),
  * digraph preparation: doubled-letter split, doubled-X alternate filler,
    odd-tail padding,
  * that the solvers actually recover a known key + plaintext on a constructed
    case (keyword dictionary attack + auto_solve), and are deterministic,
  * edge cases: empty text, non-letters, sub-digraph input, key normalisation.
"""
from __future__ import annotations

import random
import string

import pytest

from aesop.classical.playfair import (
    ALPHABET,
    build_square,
    decrypt,
    digraphs,
    encrypt,
    prepared_plaintext,
    solve,
    solve_keyword,
    auto_solve,
    Solution,
)


# --------------------------------------------------------------------------- #
# Key square
# --------------------------------------------------------------------------- #
def test_build_square_textbook():
    # The canonical Wikipedia square for this key.
    assert build_square("PLAYFAIR EXAMPLE") == "PLAYFIREXMBCDGHKNOQSTUVWZ"


def test_build_square_is_permutation_of_25_letter_alphabet():
    for key in ["", "MONARCHY", "PLAYFAIR EXAMPLE", "ZZZZ", "the quick brown fox"]:
        sq = build_square(key)
        assert len(sq) == 25
        assert sorted(sq) == sorted(ALPHABET)
        assert "J" not in sq


def test_build_square_empty_key_is_plain_alphabet():
    assert build_square("") == ALPHABET


def test_build_square_folds_j_and_dedups():
    # J folds to I, so a J in the key is absorbed by an earlier/later I.
    assert build_square("JELLY") == build_square("IELY")  # J->I, dup L dropped
    sq = build_square("BUZZ")
    assert sq.startswith("BUZ")  # dup Z dropped, only one Z near the front


# --------------------------------------------------------------------------- #
# Known-answer vectors
# --------------------------------------------------------------------------- #
def test_known_vector_hide_the_gold():
    ct = encrypt("Hide the gold in the tree stump", "PLAYFAIR EXAMPLE")
    assert ct == "BMODZBXDNABEKUDMUIXMMOUVIF"
    assert decrypt(ct, "PLAYFAIR EXAMPLE") == "HIDETHEGOLDINTHETREXESTUMP"


def test_known_vector_monarchy_instruments():
    # Classic MONARCHY example: INSTRUMENTS -> GATLMZCLRQXA.
    assert encrypt("INSTRUMENTS", "MONARCHY") == "GATLMZCLRQXA"
    assert decrypt("GATLMZCLRQXA", "MONARCHY") == "INSTRUMENTSX"


# --------------------------------------------------------------------------- #
# Digraph rules (geometry) checked directly
# --------------------------------------------------------------------------- #
def test_same_row_rule_wraps():
    # square = plain alphabet; row 0 = A B C D E.
    # A,B same row -> right neighbours -> B,C ; E,A wrap -> A,B.
    assert encrypt("AB", "") == "BC"
    assert encrypt("EA", "") == "AB"
    # decrypt is left neighbour with wrap
    assert decrypt("BC", "") == "AB"
    assert decrypt("AB", "") == "EA"


def test_same_column_rule_wraps():
    # column 0 = A F L Q V (rows 0..4). A,F same col -> below -> F,L.
    assert encrypt("AF", "") == "FL"
    # V,A wrap -> A,F  (V is bottom of column 0)
    assert encrypt("VA", "") == "AF"
    assert decrypt("FL", "") == "AF"


def test_rectangle_rule_is_self_inverse():
    # A(0,0) and G(1,1) form a rectangle -> C(0,1),F(1,0)? verify self-inverse.
    ct = encrypt("AG", "")
    assert ct != "AG"
    # Encrypting a rectangle pair twice returns it (rectangle rule = swap cols).
    assert encrypt(ct, "") == "AG"


# --------------------------------------------------------------------------- #
# Text preparation / digraphs
# --------------------------------------------------------------------------- #
def test_digraphs_split_doubled_letters():
    # TREE -> TR, EX, E(pad) : doubled EE gets an X between.
    assert digraphs("TREE") == ["TR", "EX", "EX"]


def test_digraphs_doubled_x_uses_alternate_filler():
    # A doubled X cannot be split with X; the alternate filler Q is used.
    pairs = digraphs("XX")
    assert pairs == ["XQ", "XQ"]
    # And no pair is ever a doubled letter.
    for p in pairs:
        assert p[0] != p[1]


def test_digraphs_pad_odd_tail():
    assert digraphs("ABC") == ["AB", "CX"]


def test_prepared_plaintext_matches_encrypt_input():
    # HELLOWORLD: doubled LL splits (HE LX LO ...) leaving an odd tail (D)
    # that is padded with X -> HELXLOWORLDX.
    p = "Hello, World!!"
    assert prepared_plaintext(p) == "HELXLOWORLDX"
    # prepared_plaintext is exactly what encrypt consumes: decrypt inverts to it.
    assert decrypt(encrypt(p, "KEY"), "KEY") == prepared_plaintext(p)


# --------------------------------------------------------------------------- #
# Structural invariants over random data
# --------------------------------------------------------------------------- #
def test_roundtrip_and_invariants_randomized():
    rng = random.Random(1234)
    letters = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for _ in range(500):
        n = rng.randint(0, 60)
        p = "".join(rng.choice(letters + "   xX") for _ in range(n))
        klen = rng.randint(0, 10)
        k = "".join(rng.choice(letters) for _ in range(klen))

        ct = encrypt(p, k)
        # 1. round-trip recovers the *prepared* plaintext exactly.
        assert decrypt(ct, k) == prepared_plaintext(p)
        # 2. ciphertext is all letters, even length, no J.
        assert all(c in ALPHABET for c in ct)
        assert len(ct) % 2 == 0
        assert "J" not in ct
        # 3. Playfair never emits a doubled digraph.
        for i in range(0, len(ct), 2):
            assert ct[i] != ct[i + 1]


def test_j_folds_to_i_in_plaintext():
    # JAM and IAM prepare identically (J->I) so they encrypt identically.
    assert encrypt("JAM", "KEY") == encrypt("IAM", "KEY")


def test_non_letters_and_case_ignored():
    assert encrypt("h i d e", "KEY") == encrypt("HIDE", "key")


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #
def test_empty_and_tiny_inputs():
    assert encrypt("", "KEY") == ""
    assert decrypt("", "KEY") == ""
    # single letter -> padded to one digraph, round-trips to that padded form.
    ct = encrypt("A", "KEY")
    assert len(ct) == 2
    assert decrypt(ct, "KEY") == "AX"


# --------------------------------------------------------------------------- #
# Solvers — recover a known key + plaintext on a constructed case
# --------------------------------------------------------------------------- #
# A long, unique English passage so the language model has a real gradient.
_PLAINTEXT = (
    "The quick brown fox jumps over the lazy dog near the river bank while the "
    "morning sun rises over the quiet hills and the old farmer walks slowly "
    "toward the market carrying baskets of fresh bread and cheese for the hungry "
    "travellers waiting patiently by the crossroads for the coming of the caravan"
)
_KEY = "MONARCHY"
# Small in-memory wordlist: the true key plus decoys — keeps the test fast
# instead of scanning the whole system dictionary.
_WORDS = ["monarchy", "the", "example", "cipher", "random", "playfair", "castle"]


def test_solve_keyword_recovers_key_and_plaintext():
    ct = encrypt(_PLAINTEXT, _KEY)
    expected = prepared_plaintext(_PLAINTEXT)
    sols = solve_keyword(ct, words=_WORDS, top=1, polish=False)
    assert sols, "keyword attack returned nothing"
    best = sols[0]
    assert isinstance(best, Solution)
    assert best.key == build_square(_KEY)
    assert best.plaintext == expected


def test_solve_keyword_is_deterministic():
    ct = encrypt(_PLAINTEXT, _KEY)
    a = solve_keyword(ct, words=_WORDS, top=3, polish=False)
    b = solve_keyword(ct, words=_WORDS, top=3, polish=False)
    assert [s.key for s in a] == [s.key for s in b]
    assert [s.plaintext for s in a] == [s.plaintext for s in b]


def test_solve_keyword_no_wordlist_returns_empty():
    ct = encrypt(_PLAINTEXT, _KEY)
    assert solve_keyword(ct, words=[], top=1) == []


def test_auto_solve_via_wordlist_file(tmp_path):
    ct = encrypt(_PLAINTEXT, _KEY)
    expected = prepared_plaintext(_PLAINTEXT)
    wl = tmp_path / "keys.txt"
    wl.write_text("\n".join(_WORDS) + "\n")
    sols = auto_solve(ct, wordlist_path=str(wl), top=1)
    assert sols
    assert sols[0].plaintext == expected
    assert sols[0].key == build_square(_KEY)


def test_solve_sa_runs_and_is_deterministic():
    # SA is the general (best-effort) attack; assert structure + determinism,
    # not guaranteed full recovery (that needs a denser language model).
    ct = encrypt(_PLAINTEXT, _KEY)
    a = solve(ct, restarts=1, iterations=300, seed=7, top=1)
    b = solve(ct, restarts=1, iterations=300, seed=7, top=1)
    assert a and b
    assert isinstance(a[0], Solution)
    assert sorted(a[0].key) == sorted(ALPHABET)
    # Deterministic given the same seed.
    assert a[0].key == b[0].key
    assert a[0].plaintext == b[0].plaintext


def test_solve_too_short_input():
    # Fewer than 4 letters cannot be attacked; solve degrades gracefully.
    out = solve("AB", restarts=1, iterations=10)
    assert out and isinstance(out[0], Solution)

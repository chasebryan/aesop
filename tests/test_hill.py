"""Correctness tests for the Hill cipher module (aesop.classical.hill).

These check that the cryptography is *correct* — round-trip identity, known
answer tests, real key/plaintext recovery, and the edge cases (padding, case,
non-letters, non-invertible keys) — not merely that the code runs.
"""
import numpy as np
import pytest

from aesop.classical.hill import (
    encrypt,
    decrypt,
    matrix_inverse_mod,
    determinant_mod,
    known_plaintext_attack,
    parse_matrix,
)

K2 = [[3, 3], [2, 5]]  # det = 9, coprime with 26
# A known-good, invertible 3x3 key over Z_26.
K3 = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]


# --------------------------------------------------------------------------- #
# Known-answer tests
# --------------------------------------------------------------------------- #
def test_kat_help_to_dple():
    assert encrypt("HELP", K2) == "DPLE"


def test_kat_dple_to_help():
    assert decrypt("DPLE", K2) == "HELP"


def test_kat_manual_block_math():
    # From the manual's worked example: LP -> LE under K2.
    assert encrypt("LP", K2) == "LE"


# --------------------------------------------------------------------------- #
# Round-trip identity
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "text",
    ["HELP", "ATTACKATDAWN", "THEQUICKBROWNFOX", "CRYPTANALYSIS"],
)
def test_roundtrip_2x2(text):
    ct = encrypt(text, K2)
    pt = decrypt(ct, K2)
    # decrypt of encrypt is identity up to the X-padding that fills the last block
    from aesop.core.score import clean_text
    cleaned = clean_text(text)
    while len(cleaned) % 2 != 0:
        cleaned += "X"
    assert pt == cleaned


@pytest.mark.parametrize("text", ["ACT", "HELPME", "POLYGRAPHIC", "LINEARALGEBRA"])
def test_roundtrip_3x3(text):
    ct = encrypt(text, K3)
    pt = decrypt(ct, K3)
    from aesop.core.score import clean_text
    cleaned = clean_text(text)
    while len(cleaned) % 3 != 0:
        cleaned += "X"
    assert pt == cleaned


def test_roundtrip_many_random_keys():
    rng = np.random.default_rng(1234)
    text = "MEETMEATTHEOLDMILLATNOON"
    found = 0
    for _ in range(200):
        K = rng.integers(0, 26, size=(2, 2))
        det = (int(K[0, 0]) * int(K[1, 1]) - int(K[0, 1]) * int(K[1, 0])) % 26
        if np.gcd(det, 26) != 1:
            continue
        found += 1
        assert decrypt(encrypt(text, K), K) == text
        if found >= 25:
            break
    assert found >= 5


# --------------------------------------------------------------------------- #
# matrix_inverse_mod / determinant_mod
# --------------------------------------------------------------------------- #
def test_inverse_times_matrix_is_identity_2x2():
    Kinv = matrix_inverse_mod(K2, 26)
    prod = (np.array(K2) @ Kinv) % 26
    assert np.array_equal(prod, np.eye(2, dtype=int))


def test_inverse_times_matrix_is_identity_3x3():
    Kinv = matrix_inverse_mod(K3, 26)
    prod = (np.array(K3) @ Kinv) % 26
    assert np.array_equal(prod, np.eye(3, dtype=int))


def test_determinant_mod():
    # 3*5 - 3*2 = 9
    assert determinant_mod(K2, 26) == 9


def test_noninvertible_key_raises():
    # det = 1*4 - 2*2 = 0 -> not coprime with 26
    with pytest.raises(ValueError):
        matrix_inverse_mod([[1, 2], [2, 4]], 26)


def test_noninvertible_even_det_raises():
    # det = 2*3 - 0 = 6, gcd(6,26)=2
    with pytest.raises(ValueError):
        matrix_inverse_mod([[2, 0], [0, 3]], 26)


def test_decrypt_with_bad_key_raises():
    with pytest.raises(ValueError):
        decrypt("DPLE", [[1, 2], [2, 4]])


# --------------------------------------------------------------------------- #
# Known-plaintext attack — real recovery
# --------------------------------------------------------------------------- #
def test_kpa_recovers_2x2_exactly():
    K = known_plaintext_attack("HELP", "DPLE", 2)
    assert np.array_equal(K % 26, np.array(K2))


def test_kpa_recovered_key_decrypts():
    # The recovered key must actually invert the cipher on fresh text.
    secret = K2
    pt = "ATTACKATDAWN"  # already even length, no padding added
    ct = encrypt(pt, secret)
    K = known_plaintext_attack("HELP", encrypt("HELP", secret), 2)
    assert decrypt(ct, K) == pt
    assert decrypt(ct, K) == decrypt(ct, secret)


def test_kpa_recovers_3x3():
    secret = K3
    plain = "POLYGRAPHIC"  # >= 3 blocks
    cipher = encrypt(plain, secret)
    # trim to a whole number of blocks matched (encrypt padded to 12 letters)
    from aesop.core.score import clean_text
    p = clean_text(plain)
    while len(p) % 3 != 0:
        p += "X"
    K = known_plaintext_attack(p, cipher, 3)
    assert np.array_equal(K % 26, np.array(K3))


def test_kpa_tries_other_blocks_when_first_dependent():
    # First two plaintext blocks are linearly dependent mod 26; a later
    # combination must be found so recovery still succeeds.
    secret = K2
    # Block1 = [1,2], Block2 = [2,4] (dependent), Block3 = [3,5] (independent)
    plain = "BCCEDF"  # 1,2 / 2,4 / 3,5
    cipher = encrypt(plain, secret)
    K = known_plaintext_attack(plain, cipher, 2)
    assert np.array_equal(K % 26, np.array(secret))


def test_kpa_length_mismatch_raises():
    with pytest.raises(ValueError):
        known_plaintext_attack("HELP", "DPL", 2)


def test_kpa_insufficient_text_raises():
    with pytest.raises(ValueError):
        known_plaintext_attack("HE", "DP", 2)  # only 1 block, need 2


def test_kpa_no_invertible_blocks_raises():
    # All blocks identical & non-invertible as a set.
    with pytest.raises(ValueError):
        known_plaintext_attack("AAAA", "AAAA", 2)


# --------------------------------------------------------------------------- #
# Edge cases: case, non-letters, padding
# --------------------------------------------------------------------------- #
def test_lowercase_input_is_uppercased():
    assert encrypt("help", K2) == "DPLE"


def test_nonletters_are_stripped():
    assert encrypt("H E,L.P!", K2) == "DPLE"


def test_padding_odd_length():
    # "HEL" -> "HELX", block size 2
    out = encrypt("HEL", K2)
    assert len(out) == 4
    assert decrypt(out, K2) == "HELX"


def test_decrypt_bad_length_raises():
    # 3 letters, block size 2 -> not a multiple
    with pytest.raises(ValueError):
        decrypt("ABC", K2)


# --------------------------------------------------------------------------- #
# parse_matrix
# --------------------------------------------------------------------------- #
def test_parse_matrix_infers_size():
    K = parse_matrix("3,3,2,5")
    assert np.array_equal(K, np.array(K2))


def test_parse_matrix_explicit_size():
    K = parse_matrix("6,24,1,13,16,10,20,17,15", 3)
    assert K.shape == (3, 3)


def test_parse_matrix_reduces_mod_26():
    K = parse_matrix("29,29,2,5")  # 29 == 3 mod 26
    assert np.array_equal(K, np.array(K2))


def test_parse_matrix_non_square_raises():
    with pytest.raises(ValueError):
        parse_matrix("1,2,3")  # 3 not a perfect square


def test_parse_matrix_size_mismatch_raises():
    with pytest.raises(ValueError):
        parse_matrix("1,2,3,4", 3)


def test_parse_matrix_non_numeric_raises():
    with pytest.raises(ValueError):
        parse_matrix("a,b,c,d")

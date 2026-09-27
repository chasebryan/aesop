"""
Correctness tests for aesop.classical.xor — single-byte & repeating-key XOR.

These exercise the *cryptography*, not merely that the code runs:
  * XOR involution / round-trip identity (encrypt then decrypt == identity),
  * canonical literature vectors (cryptopals Set-1: ch3 single-byte, the
    Hamming-distance sanity check, ch6-style repeating-key recovery),
  * that the solvers actually recover a KNOWN key + plaintext on constructed
    cases (single-byte, repeating-key, and auto-detect),
  * the key-length detector,
  * edge cases: empty key rejection, int keys, str/bytes coercion, non-letters,
    period reduction, and the CLI apply/solve paths.
"""
from __future__ import annotations

import base64

import pytest

from aesop.classical.xor import (
    break_repeating,
    break_single_byte,
    guess_keysize,
    hamming,
    solve,
    solve_keysize,
    xor_bytes,
    _minimize_period,
    _parse_key,
    _render_bytes,
)

# A paragraph of ordinary English — enough bytes for the block/quadgram
# analysis to lock the true key/keysize at rank 1, but still tiny.
PLAINTEXT = (
    b"The quick brown fox jumps over the lazy dog. "
    b"Attack at dawn, hold the east flank until reinforced. "
    b"We hold these truths to be self-evident and act on them."
)


# --------------------------------------------------------------------------- #
# XOR primitive: involution / round-trip
# --------------------------------------------------------------------------- #
def test_xor_is_involution_single_byte():
    for k in range(256):
        ct = xor_bytes(PLAINTEXT, k)
        assert xor_bytes(ct, k) == PLAINTEXT


def test_xor_is_involution_repeating():
    for key in (b"K", b"KEY", b"ICE", b"SPHINX", b"a longer passphrase here!"):
        ct = xor_bytes(PLAINTEXT, key)
        assert xor_bytes(ct, key) == PLAINTEXT


def test_xor_int_and_str_keys_agree_with_bytes():
    # int key == single-byte bytes key
    assert xor_bytes(PLAINTEXT, 0x58) == xor_bytes(PLAINTEXT, b"\x58")
    # str key is UTF-8 encoded
    assert xor_bytes("ABC", "K") == xor_bytes(b"ABC", b"K")
    # str data coercion
    assert xor_bytes("hello", b"K") == xor_bytes(b"hello", b"K")


def test_xor_known_vector_hex():
    # cryptopals Set-1 Challenge 2: fixed XOR
    a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    b = bytes.fromhex("686974207468652062756c6c277320657965")
    assert xor_bytes(a, b).hex() == "746865206b696420646f6e277420706c6179"


def test_xor_empty_key_rejected():
    with pytest.raises(ValueError):
        xor_bytes(PLAINTEXT, b"")


def test_xor_empty_data_ok():
    assert xor_bytes(b"", b"KEY") == b""


def test_xor_int_key_masks_to_byte():
    # 0x158 & 0xFF == 0x58
    assert xor_bytes(b"ABC", 0x158) == xor_bytes(b"ABC", 0x58)


# --------------------------------------------------------------------------- #
# Hamming distance
# --------------------------------------------------------------------------- #
def test_hamming_cryptopals_canonical():
    assert hamming(b"this is a test", b"wokka wokka!!!") == 37


def test_hamming_identity_and_symmetry():
    assert hamming(b"abc", b"abc") == 0
    assert hamming(b"abc", b"abd") == hamming(b"abd", b"abc")


def test_hamming_single_bit():
    assert hamming(b"\x00", b"\x01") == 1
    assert hamming(b"\x00", b"\xff") == 8


def test_hamming_unequal_length_counts_surplus_bits():
    # surplus 0xff byte contributes all 8 of its bits
    assert hamming(b"\x00", b"\x00\xff") == 8


# --------------------------------------------------------------------------- #
# Single-byte break
# --------------------------------------------------------------------------- #
def test_break_single_byte_cryptopals_ch3():
    ct = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )
    k, pt, _score = break_single_byte(ct)[0]
    assert k == ord("X")
    assert pt == b"Cooking MC's like a pound of bacon"


def test_break_single_byte_recovers_constructed_key():
    msg = b"Meet me by the old oak tree at midnight, bring the map."
    for k in (1, 7, 0x42, 0xAA, 0xFF):
        ct = xor_bytes(msg, k)
        rk, pt, _ = break_single_byte(ct)[0]
        assert rk == k, f"key {k:#x} not recovered (got {rk:#x})"
        assert pt == msg


def test_break_single_byte_returns_all_256_ranked():
    ranked = break_single_byte(b"hello world this is a longer sample text")
    assert len(ranked) == 256
    scores = [s for _, _, s in ranked]
    assert scores == sorted(scores, reverse=True)


# --------------------------------------------------------------------------- #
# Repeating-key break
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("key", [b"KEY", b"ICE", b"FoX!", b"AESOP", b"SPHINX"])
def test_break_repeating_recovers_key_and_plaintext(key):
    ct = xor_bytes(PLAINTEXT, key)
    rkey, pt = break_repeating(ct)
    assert rkey == key, f"expected {key!r}, got {rkey!r}"
    assert pt == PLAINTEXT


def test_solve_keysize_known_length():
    key = b"ICE"
    ct = xor_bytes(PLAINTEXT, key)
    rk = solve_keysize(ct, len(key))
    assert rk == key
    assert xor_bytes(ct, rk) == PLAINTEXT


def test_guess_keysize_ranks_true_length_high():
    key = b"SPHINX"  # length 6
    ct = xor_bytes(PLAINTEXT, key)
    ranked = guess_keysize(ct)
    top = [k for k, _ in ranked[:5]]
    # the true length or a small multiple should surface near the top
    assert 6 in top or 12 in top


def test_minimize_period():
    assert _minimize_period(b"KEYKEYKEY") == b"KEY"
    assert _minimize_period(b"ABAB") == b"AB"
    assert _minimize_period(b"XYZ") == b"XYZ"
    assert _minimize_period(b"AAAA") == b"A"


# --------------------------------------------------------------------------- #
# Auto-detect solve()
# --------------------------------------------------------------------------- #
def test_solve_autodetects_single_byte():
    msg = b"The fox knows many things but the hedgehog knows one big thing here."
    ct = xor_bytes(msg, 0x42)
    key, pt = solve(ct)
    assert key == b"\x42"
    assert pt == msg


def test_solve_autodetects_repeating():
    key = b"AESOP"
    ct = xor_bytes(PLAINTEXT, key)
    rkey, pt = solve(ct)
    assert rkey == key
    assert pt == PLAINTEXT


# --------------------------------------------------------------------------- #
# CLI helpers: key parsing & rendering
# --------------------------------------------------------------------------- #
def test_parse_key_ascii_and_hex():
    assert _parse_key("KEY", "ascii") == b"KEY"
    assert _parse_key("4b4559", "hex") == b"KEY"
    assert _parse_key("4b 45 59", "hex") == b"KEY"  # whitespace tolerated


def test_parse_key_bad_hex_raises():
    with pytest.raises(ValueError):
        _parse_key("zzzz", "hex")


def test_render_bytes_text_vs_hex():
    assert _render_bytes(b"hello world") == "hello world"
    # mostly-binary renders as hex
    blob = bytes(range(0, 32))
    assert _render_bytes(blob) == blob.hex()


# --------------------------------------------------------------------------- #
# Edge cases: non-letters, base64 payloads, structure preserved
# --------------------------------------------------------------------------- #
def test_non_letter_payload_roundtrips_exactly():
    payload = bytes(range(256))  # every byte value, incl. control + high
    ct = xor_bytes(payload, b"SPHINX")
    assert xor_bytes(ct, b"SPHINX") == payload


def test_base64_wrapped_ciphertext_breaks():
    key = b"ICE"
    ct = xor_bytes(PLAINTEXT, key)
    b64 = base64.b64encode(ct)
    # decode as the CLI would, then break
    rkey, pt = break_repeating(base64.b64decode(b64))
    assert rkey == key
    assert pt == PLAINTEXT

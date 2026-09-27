"""
Adversarial correctness tests for the AESOP *triage* module — the three
analysis commands ``identify`` (detect_cmd), ``freq`` (freq_cmd) and
``entropy`` (entropy_cmd).

These check the *analysis is correct*, not merely that it runs:

  * identify -> known-answer classification of encodings / hashes / ciphers,
  * freq -> Kasiski/IC actually recovers a known Vigenere key length from a
    constructed ciphertext (the "solver recovers the key" property for a
    triage tool), plus exact n-gram / repeated-substring counts,
  * entropy -> Shannon entropy known-answer vectors, byte-histogram invariants,
    sliding-window coverage, sparkline range/clamping,
  * edge cases: empty-ish input, non-letters, short text, single symbol.

Everything imports the programmatic API directly and uses tiny inputs so the
whole file runs in well under a second.
"""
from __future__ import annotations

import math

import pytest

from aesop.classical.vigenere import encrypt
from aesop.core.score import shannon_entropy, index_of_coincidence

from aesop.analysis.detect_cmd import quick_stats, top_guess
from aesop.core.detect import identify
from aesop.analysis.freq_cmd import (
    ngram_counts,
    repeated_substrings,
    kasiski_factors,
    likely_key_lengths,
    _classify,
)
from aesop.analysis.entropy_cmd import (
    sliding_entropy,
    byte_histogram,
    sparkline,
    _SPARK,
)


# A paragraph of ordinary English: enough letters for IC/Kasiski to be
# meaningful, small enough to stay fast.
PROSE = (
    "We hold these truths to be self evident that all men are created equal "
    "endowed by their creator with certain unalienable rights among these are "
    "life liberty and the pursuit of happiness that to secure these rights "
    "governments are instituted among men deriving their just powers"
)


# --------------------------------------------------------------------------- #
# identify — known-answer classification
# --------------------------------------------------------------------------- #
def _label(data: bytes) -> str:
    return top_guess(data).label


def test_identify_base64():
    # base64 of "Wake up, Neo!"
    assert _label(b"V2FrZSB1cCwgTmVvIQ==") == "base64"


def test_identify_md5_shaped_hash():
    g = top_guess(b"5d41402abc4b2a76b9719d911017c592")  # md5("hello")
    assert g.kind == "hash"
    assert "md5" in g.label


def test_identify_hash_lengths_by_shape():
    # (hex length -> expected family fragment)
    vectors = {
        40: "sha1",
        64: "sha256",
        128: "sha512",
    }
    for length, frag in vectors.items():
        digest = ("a1" * (length // 2))  # all-hex, correct length, has a digit
        g = top_guess(digest.encode())
        assert g.kind == "hash", (length, g)
        assert frag in g.label, (length, g.label)


def test_identify_hex_blob():
    # 24 hex chars, not a hash length -> hex encoding, not hash
    g = top_guess(b"deadbeefcafe0011223344ff")
    assert g.label == "hex"
    assert g.kind == "encoding"


def test_identify_plaintext():
    g = top_guess(PROSE.encode())
    assert g.kind == "plaintext"


def test_identify_random_bytes_is_encrypted_like():
    blob = bytes(range(256)) * 4  # uniform -> entropy 8.0, non-printable
    g = top_guess(blob)
    assert g.kind == "modern"
    assert "encrypted" in g.label or "binary" in g.label


def test_identify_never_empty_ranked_list():
    # Even nonsense yields at least one (possibly 'unknown') hypothesis.
    guesses = identify(b"\x01\x02")
    assert len(guesses) >= 1
    # sorted by confidence, descending
    confs = [g.confidence for g in guesses]
    assert confs == sorted(confs, reverse=True)


# --------------------------------------------------------------------------- #
# quick_stats — the triage shape summary
# --------------------------------------------------------------------------- #
def test_quick_stats_known_values():
    data = b"HELLO WORLD"
    st = quick_stats(data)
    assert st["length"] == len(data)
    assert st["letters"] == 10  # 'HELLOWORLD' — the space is dropped
    assert st["printable"] == pytest.approx(1.0)
    # entropy must match the core measure exactly
    assert st["entropy"] == pytest.approx(shannon_entropy(data))
    # IC must match the core measure on the latin-1 text
    assert st["ic"] == pytest.approx(index_of_coincidence(data.decode("latin-1")))


def test_quick_stats_random_entropy_near_eight():
    st = quick_stats(bytes(range(256)) * 4)
    assert st["entropy"] == pytest.approx(8.0, abs=1e-9)


# --------------------------------------------------------------------------- #
# freq — n-gram counting (exact known answers)
# --------------------------------------------------------------------------- #
def test_ngram_counts_overlapping_and_letters_only():
    # Non-letters are stripped, case-folded to upper, overlapping windows.
    assert dict(ngram_counts("ab, ab!", 2)) == {"AB": 2, "BA": 1}
    assert dict(ngram_counts("AAAA", 2)) == {"AA": 3}
    assert ngram_counts("ab", 3) == {}  # shorter than n -> empty
    # trigram totals: N-2 grams for length-N cleaned text
    text = "THEQUICKBROWNFOX"
    tri = ngram_counts(text, 3)
    assert sum(tri.values()) == len(text) - 2


def test_repeated_substrings_positions_exact():
    rep = repeated_substrings("ABCXABCXABC", 3)
    assert rep["ABC"] == [0, 4, 8]
    assert rep["BCX"] == [1, 5]
    # a substring that never repeats is absent
    assert "XAB" in rep and "FOO" not in rep


# --------------------------------------------------------------------------- #
# freq — Kasiski / IC RECOVER a known Vigenere key length
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("key", ["LEMON", "ZEUS", "THUNDER"])
def test_kasiski_recovers_true_period(key):
    """A triage tool's job: from ciphertext of an unknown period, surface the
    true key length.  We encrypt known prose and require the real period to be
    among the top-ranked candidates and to receive positive support."""
    ct = encrypt(PROSE, key)
    period = len(key)
    factors, spacings = kasiski_factors(ct)
    assert spacings, "expected some repeated-substring spacings"
    assert factors[period] > 0, f"true period {period} got no votes"
    ranked = [k for k, _ in likely_key_lengths(ct, top=6)]
    assert period in ranked[:4], (key, ranked)


def test_kasiski_ranks_lemon_period_five_first():
    """The spec case: LEMON-key ciphertext -> Kasiski ranks period 5 first."""
    ct = encrypt(PROSE + " " + PROSE, "LEMON")
    ranked = [k for k, _ in likely_key_lengths(ct, top=6)]
    assert ranked[0] == 5, ranked


def test_kasiski_only_divisors_of_gaps_get_votes():
    # Construct text with a single repeated trigram at a known spacing, using
    # non-repeating filler so ABC is the only substring that recurs.
    # "ABC" at position 0 and 12 -> gap 12 -> only divisors of 12 in 2..20 vote.
    text = "ABC" + "DEFGHIJKL" + "ABC"  # positions of ABC: 0 and 12
    factors, spacings = kasiski_factors(text)
    assert spacings == [12]
    voted = set(factors)
    assert voted == {2, 3, 4, 6, 12}


def test_likely_key_lengths_top_limit():
    ct = encrypt(PROSE, "LEMON")
    assert len(likely_key_lengths(ct, top=3)) <= 3


# --------------------------------------------------------------------------- #
# freq — IC-based family classification
# --------------------------------------------------------------------------- #
def test_classify_monoalphabetic_vs_polyalphabetic():
    caesar = encrypt(PROSE, "D")          # single-letter key == Caesar shift
    vig = encrypt(PROSE, "LEMON")         # true polyalphabetic
    assert "monoalphabetic" in _classify(index_of_coincidence(caesar))
    assert "polyalphabetic" in _classify(index_of_coincidence(vig))


def test_classify_boundaries():
    assert "monoalphabetic" in _classify(0.0667)   # English
    assert "polyalphabetic" in _classify(0.0385)   # random-ish letters
    assert "monoalphabetic" in _classify(0.10)     # above English
    assert "non-letter" in _classify(0.01) or "long-key" in _classify(0.01)


# --------------------------------------------------------------------------- #
# entropy — Shannon known-answer vectors
# --------------------------------------------------------------------------- #
def test_shannon_known_vectors():
    # four distinct bytes, equal counts -> log2(4) = 2.0  (== 'deadbeef' hex)
    assert shannon_entropy(bytes.fromhex("deadbeef")) == pytest.approx(2.0)
    # single symbol -> 0 bits/byte
    assert shannon_entropy(b"\x00" * 64) == pytest.approx(0.0, abs=1e-12)
    # uniform over 256 values -> exactly 8.0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)
    # two equally likely symbols -> 1.0
    assert shannon_entropy(b"AB" * 50) == pytest.approx(1.0)


# --------------------------------------------------------------------------- #
# entropy — sliding window
# --------------------------------------------------------------------------- #
def test_sliding_entropy_short_input_single_window():
    samples = sliding_entropy(b"hi")  # shorter than a window
    assert len(samples) == 1
    assert samples[0][0] == 0
    assert samples[0][1] == pytest.approx(shannon_entropy(b"hi"))


def test_sliding_entropy_empty():
    assert sliding_entropy(b"") == []


def test_sliding_entropy_covers_head_and_tail():
    data = bytes(range(256)) * 8  # 2048 bytes, uniform
    samples = sliding_entropy(data, window=256, step=100)
    offsets = [o for o, _ in samples]
    assert offsets[0] == 0
    # the tail window must always be represented so the end isn't missed
    assert offsets[-1] == len(data) - 256
    # every window on uniform data is high entropy
    assert all(e > 7.5 for _, e in samples)


def test_sliding_entropy_flat_on_constant_data():
    samples = sliding_entropy(b"\x00" * 1024, window=64, step=32)
    assert samples  # non-empty
    assert all(e == pytest.approx(0.0, abs=1e-12) for _, e in samples)


def test_sliding_entropy_offsets_in_range():
    data = b"".join(bytes([i % 251]) for i in range(1000))
    for off, _ in sliding_entropy(data):
        assert 0 <= off <= len(data)


# --------------------------------------------------------------------------- #
# entropy — byte histogram invariants
# --------------------------------------------------------------------------- #
def test_byte_histogram_partitions_all_bytes():
    data = b"\x00\x01\x1fAZ~\x7f\x80\xff hello"
    h = byte_histogram(data)
    assert h["null"] + h["control"] + h["printable"] + h["high"] == len(data)
    assert h["distinct"] == len(set(data))


def test_byte_histogram_bucket_boundaries():
    assert byte_histogram(b"\x00")["null"] == 1
    assert byte_histogram(b"\x1f")["control"] == 1       # < 0x20
    assert byte_histogram(b"\x7f")["control"] == 1       # DEL
    assert byte_histogram(b"\x20")["printable"] == 1     # space, first printable
    assert byte_histogram(b"\x7e")["printable"] == 1     # ~, last printable
    assert byte_histogram(b"\x80")["high"] == 1
    assert byte_histogram(b"\xff")["high"] == 1


def test_byte_histogram_distinct_count():
    assert byte_histogram(bytes(range(256)))["distinct"] == 256
    assert byte_histogram(b"AAAA")["distinct"] == 1


# --------------------------------------------------------------------------- #
# entropy — sparkline
# --------------------------------------------------------------------------- #
def test_sparkline_length_and_charset():
    line = sparkline([0.0, 2.0, 4.0, 6.0, 8.0])
    assert len(line) == 5
    assert all(ch in _SPARK for ch in line)
    # monotonic input -> monotonic (non-decreasing) glyph indices
    idxs = [_SPARK.index(ch) for ch in line]
    assert idxs == sorted(idxs)
    assert line[0] == _SPARK[0] and line[-1] == _SPARK[-1]


def test_sparkline_clamps_out_of_range():
    line = sparkline([-5.0, 100.0], vmin=0.0, vmax=8.0)
    assert line[0] == _SPARK[0]
    assert line[1] == _SPARK[-1]


def test_sparkline_empty():
    assert sparkline([]) == ""


# --------------------------------------------------------------------------- #
# cross-check: quick_stats/IC agree with encrypt round-trip properties
# --------------------------------------------------------------------------- #
def test_vigenere_lowers_ic_below_caesar():
    """Sanity round-trip on the analysis: encrypting with a longer key must push
    the index of coincidence down toward random — the very signal freq reports."""
    caesar_ic = index_of_coincidence(encrypt(PROSE, "K"))
    vig_ic = index_of_coincidence(encrypt(PROSE, "LEMON"))
    assert caesar_ic > vig_ic
    assert caesar_ic > 0.06   # monoalphabetic preserves English IC
    assert vig_ic < 0.05      # polyalphabetic flattens it

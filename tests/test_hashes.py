"""
Correctness tests for aesop.modern.hashes — hash-id, hash, crack, length-extension.

These exercise the *cryptography*, not merely that the code runs:
  * pure-Python MD5/SHA-1 match hashlib exactly across Merkle-Damgard block
    boundaries (0, 55, 56, 63, 64, 65, 200 bytes — where padding logic is fragile),
  * canonical literature test vectors: MD4 (RFC 1320), NTLM, MD5/SHA-1/SHA-256,
    CRC-32 / Adler-32,
  * hash-id ranks the right algorithm first from prefix / length / charset,
  * crack actually recovers a known preimage (verbatim word + mutation) on a
    constructed wordlist, and infers the algorithm from digest length,
  * length-extension forgeries verify against a real hashlib oracle for md5 and
    sha1 across many secret lengths (the whole point of the attack),
  * edge cases: empty input, unknown-algo errors, keylen parsing, mutation dedup.
"""
from __future__ import annotations

import hashlib
import zlib

import pytest

from aesop.modern.hashes import (
    ALGORITHMS,
    compute_all,
    compute_hash,
    dictionary_crack,
    glue_padding,
    identify_hashes,
    length_extension,
    md4,
    md5_hex,
    mutations,
    parse_keylen,
    sha1_hex,
    _ntlm,
    _MD5,
    _SHA1,
)

# Lengths that straddle every interesting Merkle-Damgard boundary:
# 55 = last that fits with padding in one block, 56 forces a second block,
# 63/64/65 = around the block size, 0 = empty, 200 = multi-block.
BOUNDARY_LENS = [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 200]


def _msg(n: int) -> bytes:
    return bytes((i * 37 + 11) & 0xFF for i in range(n))


# --------------------------------------------------------------------------- #
# Pure MD5 / SHA-1 vs hashlib across block boundaries
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("n", BOUNDARY_LENS)
def test_pure_md5_matches_hashlib(n):
    m = _msg(n)
    assert md5_hex(m) == hashlib.md5(m).hexdigest()


@pytest.mark.parametrize("n", BOUNDARY_LENS)
def test_pure_sha1_matches_hashlib(n):
    m = _msg(n)
    assert sha1_hex(m) == hashlib.sha1(m).hexdigest()


def test_md5_known_vectors():
    assert md5_hex(b"") == "d41d8cd98f00b204e9800998ecf8427e"
    assert md5_hex(b"abc") == "900150983cd24fb0d6963f7d28e17f72"
    assert md5_hex(b"The quick brown fox jumps over the lazy dog") == \
        "9e107d9d372bb6826bd81d3542a419d6"


def test_sha1_known_vectors():
    assert sha1_hex(b"") == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert sha1_hex(b"abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"


# --------------------------------------------------------------------------- #
# MD4 / NTLM literature vectors
# --------------------------------------------------------------------------- #
def test_md4_rfc1320_vectors():
    assert md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert md4(b"a").hex() == "bde52cb31de33e46245e05fbdbd6fb24"
    assert md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    assert md4(b"message digest").hex() == "d9130a8164549fe818874806e1c7014b"


def test_ntlm_known_vector():
    # NTLM('password') is a canonical, widely-published value.
    assert _ntlm(b"password") == "8846f7eaee8fb117ad06bdd830b7586c"
    assert _ntlm(b"") == "31d6cfe0d16ae931b73c59d7e0c089c0"  # MD4 of empty UTF-16LE


# --------------------------------------------------------------------------- #
# compute_hash / compute_all registry
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("algo", ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"])
def test_compute_hash_matches_hashlib(algo):
    data = b"attack at dawn"
    assert compute_hash(algo, data) == hashlib.new(algo, data).hexdigest()


def test_compute_hash_is_case_insensitive_algo():
    assert compute_hash("MD5", b"x") == compute_hash("md5", b"x")


def test_compute_hash_crc32_adler32():
    data = b"hello world"
    assert compute_hash("crc32", data) == format(zlib.crc32(data) & 0xFFFFFFFF, "08x")
    assert compute_hash("adler32", data) == format(zlib.adler32(data) & 0xFFFFFFFF, "08x")


def test_compute_hash_ntlm_via_registry():
    assert compute_hash("ntlm", b"password") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_compute_hash_unknown_algo_raises():
    with pytest.raises(ValueError):
        compute_hash("definitely-not-a-hash", b"x")


def test_compute_all_returns_registered_and_valid():
    rows = compute_all(b"hi", ["md5", "sha1", "sha256"])
    d = dict(rows)
    assert d["md5"] == hashlib.md5(b"hi").hexdigest()
    assert d["sha256"] == hashlib.sha256(b"hi").hexdigest()
    assert len(rows) == 3


def test_compute_all_default_covers_full_registry():
    rows = compute_all(b"x")
    assert len(rows) == len(ALGORITHMS)


# --------------------------------------------------------------------------- #
# hash-id: identification ranking
# --------------------------------------------------------------------------- #
def test_identify_md5_ranks_first_at_32_hex():
    g = identify_hashes("5f4dcc3b5aa765d61d8327deb882cf99")
    assert g[0].name == "md5"
    names = [x.name for x in g]
    assert "ntlm" in names and "md4" in names


def test_identify_sha1_at_40_hex():
    g = identify_hashes("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert g[0].name == "sha1"


def test_identify_sha256_at_64_hex():
    g = identify_hashes("a" * 64)
    assert g[0].name == "sha256"


def test_identify_bcrypt_prefix():
    g = identify_hashes("$2b$12$" + "a" * 53)
    assert g[0].name == "bcrypt"
    assert g[0].confidence >= 0.95


def test_identify_sha512crypt_prefix():
    g = identify_hashes("$6$salt$" + "a" * 86)
    assert g[0].name == "sha512crypt"


def test_identify_mysql41():
    g = identify_hashes("*" + "A" * 40)
    assert g[0].name == "mysql41"


def test_identify_empty_and_garbage():
    assert identify_hashes("")[0].name == "unknown"
    assert identify_hashes("   ")[0].name == "unknown"
    # A non-hex, non-prefixed short token is unknown, never a confident guess.
    g = identify_hashes("!!not-a-hash!!")
    assert g[0].confidence <= 0.3


def test_identify_whitespace_tolerant():
    g = identify_hashes("  5f4dcc3b5aa765d61d8327deb882cf99  ")
    assert g[0].name == "md5"


def test_identify_confidence_sorted_desc():
    g = identify_hashes("a" * 64)
    confs = [x.confidence for x in g]
    assert confs == sorted(confs, reverse=True)


# --------------------------------------------------------------------------- #
# crack: dictionary attack recovers a known preimage
# --------------------------------------------------------------------------- #
@pytest.fixture()
def wordlist(tmp_path):
    words = ["apple", "cipher", "dragon", "hunter", "monkey", "orange",
             "secret", "shadow", "password", "letmein", "sunshine"]
    p = tmp_path / "words.txt"
    p.write_text("\n".join(words) + "\n", encoding="utf-8")
    return str(p)


def test_crack_recovers_verbatim_word_md5(wordlist):
    target = hashlib.md5(b"cipher").hexdigest()
    pre, tried = dictionary_crack(target, "md5", wordlist)
    assert pre == "cipher"
    assert tried >= 1


def test_crack_recovers_mutation(wordlist):
    # 'cipher123' is only reachable via the suffix mutations.
    target = hashlib.md5(b"cipher123").hexdigest()
    pre, _ = dictionary_crack(target, "md5", wordlist, with_mutations=True)
    assert pre == "cipher123"


def test_crack_recovers_capitalized_mutation(wordlist):
    target = hashlib.md5(b"Dragon").hexdigest()
    pre, _ = dictionary_crack(target, "md5", wordlist, with_mutations=True)
    assert pre == "Dragon"


def test_crack_sha1_and_ntlm(wordlist):
    t_sha1 = hashlib.sha1(b"secret").hexdigest()
    assert dictionary_crack(t_sha1, "sha1", wordlist)[0] == "secret"
    t_ntlm = _ntlm(b"password")
    assert dictionary_crack(t_ntlm, "ntlm", wordlist)[0] == "password"


def test_crack_miss_returns_none(wordlist):
    target = hashlib.md5(b"this-word-is-not-in-the-list-xyz").hexdigest()
    pre, tried = dictionary_crack(target, "md5", wordlist)
    assert pre is None
    assert tried > 0


def test_crack_no_mutations_misses_mutation(wordlist):
    target = hashlib.md5(b"cipher123").hexdigest()
    pre, _ = dictionary_crack(target, "md5", wordlist, with_mutations=False)
    assert pre is None  # verbatim-only cannot reach the suffix form


def test_crack_max_candidates_cap(wordlist):
    target = hashlib.md5(b"cipher").hexdigest()
    captured = {}

    def cb(tried, capped):
        captured["capped"] = capped

    pre, tried = dictionary_crack(
        target, "md5", wordlist, max_candidates=2, progress_cb=cb
    )
    assert pre is None  # capped before reaching 'cipher'
    assert tried <= 2
    assert captured.get("capped") is True


def test_crack_unknown_algo_raises(wordlist):
    with pytest.raises(ValueError):
        dictionary_crack("00", "nope", wordlist)


# --------------------------------------------------------------------------- #
# mutations
# --------------------------------------------------------------------------- #
def test_mutations_are_deduplicated():
    ms = list(mutations("word"))
    assert len(ms) == len(set(ms))


def test_mutations_include_case_and_suffix():
    ms = set(mutations("cat"))
    assert {"cat", "CAT", "Cat"} <= ms
    assert "cat1" in ms and "cat123" in ms and "cat!" in ms


# --------------------------------------------------------------------------- #
# length-extension: forgeries verify against a real hashlib oracle
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("algo,hf", [("md5", hashlib.md5), ("sha1", hashlib.sha1)])
@pytest.mark.parametrize("keylen", [0, 1, 5, 15, 16, 55, 56, 63, 64, 100])
def test_length_extension_forgery_verifies(algo, hf, keylen):
    secret = b"K" * keylen
    data = b"user=guest&role=user"
    append = b"&role=admin"
    known = hf(secret + data).hexdigest()

    forged, new_hash = length_extension(algo, known, data, append, keylen)

    # The forged suffix is exactly data + glue + append ...
    assert forged.startswith(data)
    assert forged.endswith(append)
    # ... and the oracle H(secret + forged) equals the forged digest.
    assert hf(secret + forged).hexdigest() == new_hash


def test_length_extension_empty_append():
    secret, data = b"K" * 16, b"payload"
    known = hashlib.md5(secret + data).hexdigest()
    forged, new_hash = length_extension("md5", known, data, b"", 16)
    assert hashlib.md5(secret + forged).hexdigest() == new_hash


def test_length_extension_bad_digest_length_raises():
    with pytest.raises(ValueError):
        length_extension("md5", "abcd", b"", b"", 16)  # too short for md5


def test_length_extension_unsupported_algo_raises():
    with pytest.raises(ValueError):
        length_extension("sha256", "a" * 64, b"", b"", 16)


def test_glue_padding_lands_on_block_boundary():
    for n in [0, 1, 55, 56, 63, 64, 100]:
        pad = glue_padding("md5", n)
        assert (n + len(pad)) % 64 == 0
        assert pad[0] == 0x80


def test_pure_hash_padding_matches_glue_for_fresh_hash():
    # A fresh MD5 of an N-byte message uses exactly padding(N).
    n = 40
    assert _MD5.padding(n) == glue_padding("md5", n)
    assert _SHA1.padding(n) == glue_padding("sha1", n)


# --------------------------------------------------------------------------- #
# parse_keylen
# --------------------------------------------------------------------------- #
def test_parse_keylen_single():
    assert parse_keylen("16") == [16]


def test_parse_keylen_range_dash_and_colon():
    assert parse_keylen("8-16") == list(range(8, 17))
    assert parse_keylen("8:16") == list(range(8, 17))


def test_parse_keylen_reversed_range_normalized():
    assert parse_keylen("16-8") == list(range(8, 17))


def test_parse_keylen_list():
    assert parse_keylen("8,12,16") == [8, 12, 16]


def test_parse_keylen_empty_raises():
    with pytest.raises(ValueError):
        parse_keylen("")

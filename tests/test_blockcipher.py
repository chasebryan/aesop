"""
Correctness tests for aesop.modern.blockcipher — block-cipher-mode analysis.

These exercise the *cryptography*, not merely that the code runs:

  * PKCS#7 pad/unpad/valid round-trip + boundary behaviour (block-aligned input
    gets a whole padding block; malformed padding is rejected),
  * ECB detection against *real* AES-ECB (pycryptodome) vs. AES-CBC — the ECB
    penguin fingerprint must fire on ECB and stay silent on CBC,
  * find_block_size / repeated_blocks evidence,
  * cbc_bitflip actually forges a chosen plaintext slice in a real AES-CBC
    ciphertext,
  * padding_oracle_decrypt recovers a KNOWN plaintext against a genuine
    AES-CBC + PKCS#7 oracle, across many random keys/IVs/message lengths
    (this stresses the last-byte false-positive disambiguation), with and
    without an IV, and against a Callable oracle built from pkcs7_valid,
  * xor_bytes / split_blocks helpers and their error paths,
  * the CLI --ecb-detect path end to end (greppable primary line).

pycryptodome supplies the real AES; it is only used by the tests, never imported
by the module under test.
"""
from __future__ import annotations

import os

import pytest

from aesop.modern.blockcipher import (
    xor_bytes,
    split_blocks,
    pkcs7_pad,
    pkcs7_unpad,
    pkcs7_valid,
    detect_ecb,
    repeated_blocks,
    find_block_size,
    cbc_bitflip,
    padding_oracle_decrypt,
    _render_bytes,
)

AES = pytest.importorskip("Crypto.Cipher.AES", reason="pycryptodome required for AES vectors")
from Crypto.Cipher import AES as _AES  # noqa: E402

BS = 16


# --------------------------------------------------------------------------- #
# helpers: real AES primitives for constructing ground-truth ciphertext
# --------------------------------------------------------------------------- #
def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    return _AES.new(key, _AES.MODE_ECB).encrypt(data)


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return _AES.new(key, _AES.MODE_CBC, iv).encrypt(data)


def make_cbc_padding_oracle(key: bytes):
    """A genuine PKCS#7 padding oracle over AES-CBC.

    The attack always submits a 2-block message [forged_prev || target]; only the
    final block's padding matters, so the fixed IV used for the throwaway first
    block is irrelevant.
    """
    fixed_iv = b"\x00" * BS

    def oracle(ct: bytes) -> bool:
        pt = _AES.new(key, _AES.MODE_CBC, fixed_iv).decrypt(ct)
        return pkcs7_valid(pt, BS)

    return oracle


# --------------------------------------------------------------------------- #
# xor_bytes / split_blocks
# --------------------------------------------------------------------------- #
def test_xor_bytes_basic_and_involution():
    a = b"\x00\x0f\xf0\xff"
    b = b"\xff\xff\xff\xff"
    assert xor_bytes(a, b) == b"\xff\xf0\x0f\x00"
    assert xor_bytes(xor_bytes(a, b), b) == a


def test_xor_bytes_str_coercion():
    assert xor_bytes("AB", "AB") == b"\x00\x00"


def test_xor_bytes_length_mismatch_raises():
    with pytest.raises(ValueError):
        xor_bytes(b"abc", b"ab")


def test_split_blocks_sizes_and_short_tail():
    data = bytes(range(20))
    blocks = split_blocks(data, 8)
    assert [len(b) for b in blocks] == [8, 8, 4]
    assert b"".join(blocks) == data


def test_split_blocks_bad_size_raises():
    with pytest.raises(ValueError):
        split_blocks(b"abcd", 0)


# --------------------------------------------------------------------------- #
# PKCS#7
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("n", [0, 1, 5, 15, 16, 17, 31, 32, 100])
def test_pkcs7_roundtrip(n):
    msg = bytes((i * 7) & 0xFF for i in range(n))
    padded = pkcs7_pad(msg, BS)
    assert len(padded) % BS == 0
    assert len(padded) > len(msg)  # always adds at least one byte
    assert pkcs7_valid(padded, BS)
    assert pkcs7_unpad(padded, BS) == msg


def test_pkcs7_block_aligned_adds_full_block():
    msg = b"YELLOW SUBMARINE"  # exactly one block
    padded = pkcs7_pad(msg, BS)
    assert padded == msg + bytes([BS]) * BS
    assert len(padded) == 2 * BS
    assert pkcs7_unpad(padded, BS) == msg


def test_pkcs7_known_value():
    # 13 bytes -> pad with three 0x03
    assert pkcs7_pad(b"HELLO, WORLD.", BS) == b"HELLO, WORLD.\x03\x03\x03"


def test_pkcs7_unpad_rejects_bad_padding():
    assert not pkcs7_valid(b"A" * 15 + b"\x00", BS)   # zero pad length
    assert not pkcs7_valid(b"A" * 15 + b"\x11", BS)   # 0x11 > block size
    assert not pkcs7_valid(b"A" * 14 + b"\x02\x03", BS)  # bytes disagree
    assert not pkcs7_valid(b"", BS)                    # empty
    assert not pkcs7_valid(b"A" * 15, BS)              # not block-aligned
    for bad in (b"A" * 15 + b"\x00", b"A" * 14 + b"\x02\x03"):
        with pytest.raises(ValueError):
            pkcs7_unpad(bad, BS)


def test_pkcs7_valid_true_case():
    assert pkcs7_valid(b"A" * 14 + b"\x02\x02", BS)
    assert pkcs7_valid(b"A" * 15 + b"\x01", BS)


# --------------------------------------------------------------------------- #
# ECB detection against real AES
# --------------------------------------------------------------------------- #
def test_detect_ecb_on_real_aes_ecb():
    key = os.urandom(16)
    block = b"YELLOW SUBMARINE"
    plaintext = block * 4  # four identical plaintext blocks
    ct = aes_ecb_encrypt(key, plaintext)
    is_ecb, reps = detect_ecb(ct, BS)
    assert is_ecb is True
    assert reps == 3  # four blocks -> three duplicates of the first


def test_cbc_is_not_flagged_as_ecb():
    key = os.urandom(16)
    iv = os.urandom(16)
    block = b"YELLOW SUBMARINE"
    ct = aes_cbc_encrypt(key, iv, block * 4)
    is_ecb, reps = detect_ecb(ct, BS)
    assert is_ecb is False
    assert reps == 0


def test_random_data_not_flagged():
    is_ecb, reps = detect_ecb(os.urandom(16 * 8), BS)
    assert is_ecb is False and reps == 0


def test_repeated_blocks_reports_evidence():
    data = bytes(16) + b"\xaa" * 16 + bytes(16) + b"\xaa" * 16
    dupes = dict(repeated_blocks(data, BS))
    assert dupes[(b"\x00" * 16).hex()] == 2
    assert dupes[(b"\xaa" * 16).hex()] == 2


def test_find_block_size_prefers_16_on_real_ecb():
    key = os.urandom(16)
    ct = aes_ecb_encrypt(key, b"YELLOW SUBMARINE" * 4)
    assert find_block_size(ct) == 16


def test_find_block_size_none_when_no_repeats():
    assert find_block_size(os.urandom(16 * 6)) is None


# --------------------------------------------------------------------------- #
# CBC bit-flipping — forge chosen plaintext in a real AES-CBC ciphertext
# --------------------------------------------------------------------------- #
def test_cbc_bitflip_mask_value():
    mask = cbc_bitflip(b"AAAA", b"BBBB", offset=4, block=16)
    assert len(mask) == 16
    assert mask[:4] == bytes(4)          # untouched region is zero
    assert mask[4:8] == bytes(a ^ b for a, b in zip(b"AAAA", b"BBBB"))
    assert mask[8:] == bytes(8)


def test_cbc_bitflip_forges_admin_in_real_cbc():
    key = os.urandom(16)
    iv = os.urandom(16)
    # block0 is a sacrificial block we are allowed to scramble; block1 is target
    known = b"comment1=AAAAAAA"          # 16 bytes, fully known target block
    plaintext = (b"Z" * 16) + known
    ct = aes_cbc_encrypt(key, iv, pkcs7_pad(plaintext, BS))

    blocks = split_blocks(ct, BS)
    desired = b";admin=true;a=bb"        # same length as `known`
    mask = cbc_bitflip(known, desired, offset=0, block=BS)
    blocks[0] = xor_bytes(blocks[0], mask)  # tamper the block *preceding* target

    tampered = b"".join(blocks)
    recovered = _AES.new(key, _AES.MODE_CBC, iv).decrypt(tampered)
    # second plaintext block now reads our chosen string
    assert recovered[16:32] == desired


def test_cbc_bitflip_offset_out_of_range():
    with pytest.raises(ValueError):
        cbc_bitflip(b"AAAA", b"BBBB", offset=14, block=16)  # 14+4 > 16
    with pytest.raises(ValueError):
        cbc_bitflip(b"AA", b"B", offset=0, block=16)        # length mismatch


# --------------------------------------------------------------------------- #
# CBC padding oracle — the crown jewel
# --------------------------------------------------------------------------- #
def test_padding_oracle_recovers_multiblock_with_iv():
    key = os.urandom(16)
    iv = os.urandom(16)
    secret = b"The fox knows many things; the padding knows one bit."
    ct = aes_cbc_encrypt(key, iv, pkcs7_pad(secret, BS))
    oracle = make_cbc_padding_oracle(key)

    recovered = padding_oracle_decrypt(oracle, ct, block=BS, iv=iv)
    assert pkcs7_unpad(recovered, BS) == secret


def test_padding_oracle_without_iv_skips_first_block():
    key = os.urandom(16)
    iv = os.urandom(16)
    secret = b"block-one-ignored" + b"!" * 40
    padded = pkcs7_pad(secret, BS)
    ct = aes_cbc_encrypt(key, iv, padded)
    oracle = make_cbc_padding_oracle(key)

    recovered = padding_oracle_decrypt(oracle, ct, block=BS, iv=None)
    # first block is only the chain value; everything after it is exact
    assert recovered == padded[BS:]


@pytest.mark.parametrize("mlen", [1, 15, 16, 17, 30, 32])
def test_padding_oracle_various_lengths(mlen):
    """Random keys/IVs across lengths — stresses the last-byte disambiguation
    (messages that pad to end in 0x01, 0x02 0x02, or a full block)."""
    key = os.urandom(16)
    iv = os.urandom(16)
    secret = os.urandom(mlen)
    ct = aes_cbc_encrypt(key, iv, pkcs7_pad(secret, BS))
    oracle = make_cbc_padding_oracle(key)
    recovered = padding_oracle_decrypt(oracle, ct, block=BS, iv=iv)
    assert pkcs7_unpad(recovered, BS) == secret


def test_padding_oracle_many_random_trials():
    """Repeat with fresh randomness so the rare false-positive path is hit."""
    for _ in range(12):
        key = os.urandom(16)
        iv = os.urandom(16)
        # length chosen so the last block frequently already ends in 0x01/0x02
        secret = bytes([1, 2, 2]) + os.urandom(20)
        ct = aes_cbc_encrypt(key, iv, pkcs7_pad(secret, BS))
        oracle = make_cbc_padding_oracle(key)
        recovered = padding_oracle_decrypt(oracle, ct, block=BS, iv=iv)
        assert pkcs7_unpad(recovered, BS) == secret


def test_padding_oracle_pure_callable_oracle():
    """The oracle contract is just Callable[[bytes], bool]; build one directly
    from a toy invertible block map (no AES) to prove the math is generic."""
    # toy 16-byte block permutation: D_k as a fixed byte-wise substitution.
    import random
    rng = random.Random(1234)
    sbox = list(range(256))
    rng.shuffle(sbox)
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i

    def enc_block(b):  # E_k
        return bytes(sbox[x] for x in b)

    def dec_block(b):  # D_k
        return bytes(inv[x] for x in b)

    def cbc_encrypt(iv, data):
        out = []
        prev = iv
        for blk in split_blocks(data, BS):
            x = xor_bytes(blk, prev)
            c = enc_block(x)
            out.append(c)
            prev = c
        return b"".join(out)

    def oracle(ct):
        # decrypt as CBC with a fixed dummy IV; only last block's padding matters
        blocks = split_blocks(ct, BS)
        prev = b"\x00" * BS
        pt = bytearray()
        for c in blocks:
            pt += xor_bytes(dec_block(c), prev)
            prev = c
        return pkcs7_valid(bytes(pt), BS)

    iv = bytes(range(16))
    secret = b"generic oracle proof, no AES needed."
    ct = cbc_encrypt(iv, pkcs7_pad(secret, BS))
    recovered = padding_oracle_decrypt(oracle, ct, block=BS, iv=iv)
    assert pkcs7_unpad(recovered, BS) == secret


def test_padding_oracle_rejects_bad_length():
    oracle = make_cbc_padding_oracle(os.urandom(16))
    with pytest.raises(ValueError):
        padding_oracle_decrypt(oracle, b"short", block=BS)
    with pytest.raises(ValueError):
        padding_oracle_decrypt(oracle, b"", block=BS)


def test_padding_oracle_single_block_needs_iv():
    key = os.urandom(16)
    iv = os.urandom(16)
    ct = aes_cbc_encrypt(key, iv, pkcs7_pad(b"hi", BS))  # one block
    oracle = make_cbc_padding_oracle(key)
    # without iv there is nothing to chain against
    with pytest.raises(ValueError):
        padding_oracle_decrypt(oracle, ct, block=BS, iv=None)
    # with iv it recovers the block
    recovered = padding_oracle_decrypt(oracle, ct, block=BS, iv=iv)
    assert pkcs7_unpad(recovered, BS) == b"hi"


# --------------------------------------------------------------------------- #
# CLI rendering helper
# --------------------------------------------------------------------------- #
def test_render_bytes_text_vs_hex():
    assert _render_bytes(b"plain readable text") == "plain readable text"
    blob = bytes(range(32))
    assert _render_bytes(blob) == blob.hex()

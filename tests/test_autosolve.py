"""Tests for the ``auto`` flagship solver (aesop.analysis.autosolve)."""
from __future__ import annotations

import base64
import binascii

import pytest

from aesop.analysis.autosolve import auto_solve, rank_score, peel_encodings
from aesop.classical.caesar import shift
from aesop.classical.vigenere import encrypt as vig_encrypt
from aesop.classical.xor import xor_bytes


def _best_text(data, **kw):
    res = auto_solve(data, **kw)
    assert res, "auto_solve returned no candidates"
    return res[0]


def test_passthrough_plaintext_flag():
    r = _best_text(b"flag{already_here}")
    assert r.is_flag and b"flag{already_here}" == r.data


def test_solves_caesar():
    ct = shift("Hello, world! this is a simple caesar test message", 13).encode()
    r = _best_text(ct, flag_re=None)
    assert b"Hello, world" in r.data


def test_peels_nested_encoding_to_flag():
    payload = binascii.hexlify(base64.b64encode(b"flag{auto_solver_works}"))
    r = _best_text(payload)
    assert r.is_flag
    assert r.data == b"flag{auto_solver_works}"
    assert r.steps == ["from-hex", "from-base64"]


def test_peel_encodings_finds_layers():
    payload = base64.b64encode(b"the answer is hidden here inside")
    nodes = peel_encodings(payload, depth=4, flag_pat=None)
    assert any(b"the answer is hidden" in d for _, d in nodes)


def test_solves_single_byte_xor():
    pt = b"The fox knows many things but the hedgehog knows one big thing indeed."
    ct = bytes(b ^ 42 for b in pt).hex().encode()  # hex-wrapped, like a challenge
    r = _best_text(ct, flag_re=None)
    assert b"The fox knows many things" in r.data


def test_solves_repeating_xor():
    pt = b"Attack at dawn, hold the line until dusk and do not retreat under any circumstances"
    ct = xor_bytes(pt, b"FOX").hex().encode()
    r = _best_text(ct, flag_re=None)
    assert b"Attack at dawn" in r.data


def test_solves_vigenere():
    pt = ("the fox waited patiently by the hedge until the careless crow "
          "dropped its cheese to the ground below")
    ct = vig_encrypt(pt, "lemon").encode()
    r = _best_text(ct, flag_re=None, expensive_budget=4)
    assert b"the fox waited patiently" in r.data


def test_flag_stops_search():
    payload = base64.b64encode(b"CTF{layered_and_solved}")
    r = _best_text(payload, flag_re=r"CTF\{.*\}")
    assert r.is_flag and r.data == b"CTF{layered_and_solved}"


def test_ranking_prefers_english():
    assert rank_score(b"the quick brown fox jumps over the lazy dog") > rank_score(b"xqzjkvbwpmqxzjkvbwpm")

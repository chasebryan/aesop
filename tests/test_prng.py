"""
Correctness tests for aesop.modern.prng — predicting non-cryptographic PRNGs.

These check the *mathematics*, not merely that the code runs:
  * MT19937: temper/untemper is a true inverse; a known-answer reference vector
    (init_genrand(5489)); a cloned generator reproduces CPython's random module
    EXACTLY, both on a 624-aligned window and on an unaligned one.
  * LCG: recover (a, c, m) on constructed cases with literature constants
    (glibc, MSVC, MINSTD, java.util.Random, MMIX), with the modulus both known
    and recovered-from-scratch (including the power-of-two overshoot hazard);
    predictions match the real generator's future output.
  * edge cases: refusal on too-little data, 32-bit range enforcement, number
    stream parsing (JSON / whitespace / commas / hex), c == 0.

Everything runs on tiny sequences so the whole file finishes well under 10s.
"""
from __future__ import annotations

import json
import random

import pytest

from aesop.modern.prng import (
    MT19937,
    MT19937Predictor,
    LCGParams,
    temper,
    untemper,
    mt19937_recover,
    lcg_recover,
    lcg_recover_modulus,
    lcg_recover_multiplier,
    parse_number_stream,
    _intish,
    _N,
    _MASK32,
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def lcg_stream(a: int, c: int, m: int, seed: int, n: int) -> list:
    """Produce ``n`` consecutive outputs of x -> (a*x + c) mod m."""
    x = seed
    out = []
    for _ in range(n):
        x = (a * x + c) % m
        out.append(x)
    return out


# literature LCG constants: (name, a, c, m, seed)
LCG_CASES = [
    ("glibc 2^31", 1103515245, 12345, 2 ** 31, 42),
    ("MSVC 2^32", 214013, 2531011, 2 ** 32, 7),
    ("MINSTD c=0 2^31-1", 16807, 0, 2 ** 31 - 1, 99),
    ("java 2^48", 0x5DEECE66D, 0xB, 2 ** 48, 0x1234ABCD),
    ("MMIX 2^64", 6364136223846793005, 1442695040888963407, 2 ** 64, 123456789),
]


# --------------------------------------------------------------------------- #
# MT19937 — tempering is an exact bijection
# --------------------------------------------------------------------------- #
def test_untemper_inverts_temper_edge_values():
    for x in (0, 1, 2, _MASK32, _MASK32 - 1, 0x80000000, 0x7FFFFFFF, 0xDEADBEEF):
        assert untemper(temper(x)) == x


def test_untemper_inverts_temper_random_sample():
    rng = random.Random(20240501)
    for _ in range(2000):
        x = rng.getrandbits(32)
        assert untemper(temper(x)) == x
        # and the other direction: temper(untemper(y)) == y for any 32-bit y
        y = rng.getrandbits(32)
        assert temper(untemper(y)) == y


def test_mt19937_known_answer_vector():
    # Reference mt19937ar init_genrand(5489): the canonical first outputs.
    mt = MT19937.from_seed(5489)
    got = [mt.next_uint32() for _ in range(5)]
    assert got == [3499211612, 581869302, 3890346734, 3586334585, 545404204]


# --------------------------------------------------------------------------- #
# MT19937 — clone reproduces CPython's random module EXACTLY
# --------------------------------------------------------------------------- #
def test_clone_matches_cpython_random_aligned():
    r = random.Random(12345)
    outs = [r.getrandbits(32) for _ in range(_N)]        # exactly one state's worth
    predictor = mt19937_recover(outs)
    assert isinstance(predictor, MT19937Predictor)
    predicted = predictor.predict_next(50)
    actual = [r.getrandbits(32) for _ in range(50)]
    assert predicted == actual


def test_clone_matches_cpython_random_unaligned():
    # Consume some outputs first so the 624 window is NOT block-aligned.
    r = random.Random(0xC0FFEE)
    for _ in range(97):
        r.getrandbits(32)
    outs = [r.getrandbits(32) for _ in range(_N)]
    predictor = mt19937_recover(outs)
    predicted = predictor.predict_next(30)
    actual = [r.getrandbits(32) for _ in range(30)]
    assert predicted == actual


def test_clone_uses_last_624_when_given_more():
    r = random.Random(555)
    outs = [r.getrandbits(32) for _ in range(_N + 200)]   # extra history
    predictor = mt19937_recover(outs)
    predicted = predictor.predict_next(20)
    actual = [r.getrandbits(32) for _ in range(20)]
    assert predicted == actual


def test_clone_recovered_state_round_trips_through_setstate():
    # The 624 recovered words must be a valid CPython random state.
    r = random.Random(2718281828)
    outs = [r.getrandbits(32) for _ in range(_N)]
    state = mt19937_recover(outs).state()
    assert len(state) == _N
    clone = random.Random()
    clone.setstate((3, tuple(state) + (_N,), None))
    assert [clone.getrandbits(32) for _ in range(10)] == \
           [r.getrandbits(32) for _ in range(10)]


def test_mt_from_outputs_requires_624():
    with pytest.raises(ValueError):
        MT19937.from_outputs([1, 2, 3])
    with pytest.raises(ValueError):
        mt19937_recover(list(range(_N - 1)))


def test_mt19937_state_length_validated():
    with pytest.raises(ValueError):
        MT19937([1, 2, 3])


# --------------------------------------------------------------------------- #
# LCG — recovery with a KNOWN modulus (3 outputs suffice)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,a,c,m,seed", LCG_CASES)
def test_lcg_known_modulus_recovers_params(name, a, c, m, seed):
    seq = lcg_stream(a, c, m, seed, 5)
    params = lcg_recover(seq[:3], modulus=m)
    assert params.a == a, name
    assert params.c == c, name
    assert params.m == m, name
    assert params.reproduces(seq[:3]), name


@pytest.mark.parametrize("name,a,c,m,seed", LCG_CASES)
def test_lcg_known_modulus_predicts_future(name, a, c, m, seed):
    seq = lcg_stream(a, c, m, seed, 12)
    params = lcg_recover(seq[:6], modulus=m)
    predicted = params.predict_next(6)
    assert predicted == seq[6:12], name


# --------------------------------------------------------------------------- #
# LCG — recovery with an UNKNOWN modulus (the harder attack)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,a,c,m,seed", LCG_CASES)
def test_lcg_unknown_modulus_recovers_everything(name, a, c, m, seed):
    seq = lcg_stream(a, c, m, seed, 20)
    params = lcg_recover(seq, modulus=None)
    # crucially the modulus must be EXACT, not a multiple (power-of-two hazard)
    assert params.m == m, f"{name}: got m={params.m}"
    assert params.a == a, name
    assert params.c == c, name


@pytest.mark.parametrize("name,a,c,m,seed", LCG_CASES)
def test_lcg_unknown_modulus_predicts_holdout(name, a, c, m, seed):
    seq = lcg_stream(a, c, m, seed, 20)
    # recover from all but the last three, then predict them
    params = lcg_recover(seq[:-3], modulus=None)
    predicted = params.predict_next(3)
    assert predicted == seq[-3:], name


@pytest.mark.parametrize("name,a,c,m,seed", LCG_CASES)
def test_lcg_recover_modulus_helper(name, a, c, m, seed):
    seq = lcg_stream(a, c, m, seed, 20)
    assert lcg_recover_modulus(seq) == m, name


def test_lcg_recover_multiplier_with_known_modulus():
    a, c, m = 1103515245, 12345, 2 ** 31
    seq = lcg_stream(a, c, m, 42, 5)
    assert lcg_recover_multiplier(seq, m) == a


def test_lcg_c_zero_is_recovered():
    # MINSTD: increment is exactly zero — must come back as 0, not m.
    a, c, m = 16807, 0, 2 ** 31 - 1
    seq = lcg_stream(a, c, m, 1, 20)
    params = lcg_recover(seq, modulus=None)
    assert params.c == 0
    assert params.a == a and params.m == m


# --------------------------------------------------------------------------- #
# LCGParams behaviour
# --------------------------------------------------------------------------- #
def test_lcgparams_reproduces_true_and_false():
    a, c, m = 214013, 2531011, 2 ** 32
    seq = lcg_stream(a, c, m, 7, 10)
    good = LCGParams(a=a, c=c, m=m, last=seq[-1])
    assert good.reproduces(seq)
    bad = LCGParams(a=a + 1, c=c, m=m, last=seq[-1])
    assert not bad.reproduces(seq)


def test_lcgparams_predict_continues_stream():
    a, c, m = 214013, 2531011, 2 ** 32
    seq = lcg_stream(a, c, m, 7, 15)
    params = lcg_recover(seq[:10], modulus=m)
    # prediction must continue from seq[9], i.e. equal seq[10:]
    assert params.predict_next(5) == seq[10:15]


# --------------------------------------------------------------------------- #
# LCG — refusals on insufficient data
# --------------------------------------------------------------------------- #
def test_lcg_too_few_outputs_known_modulus():
    with pytest.raises(ValueError):
        lcg_recover([5, 9], modulus=2 ** 31)


def test_lcg_too_few_outputs_unknown_modulus():
    a, c, m = 1103515245, 12345, 2 ** 31
    seq = lcg_stream(a, c, m, 42, 4)   # < 6, cannot recover an unknown modulus
    with pytest.raises(ValueError):
        lcg_recover(seq, modulus=None)


def test_lcg_recover_modulus_none_on_short_input():
    assert lcg_recover_modulus([1, 2, 3]) is None


# --------------------------------------------------------------------------- #
# number-stream parsing / int coercion (CLI input plumbing)
# --------------------------------------------------------------------------- #
def test_parse_number_stream_json_array():
    assert parse_number_stream("[1, 22, 333]") == [1, 22, 333]


def test_parse_number_stream_whitespace_and_newlines():
    assert parse_number_stream("1\n2\n3\n") == [1, 2, 3]
    assert parse_number_stream("  10   20\t30 ") == [10, 20, 30]


def test_parse_number_stream_commas_and_prose():
    assert parse_number_stream("outputs: 5, 6, 7") == [5, 6, 7]


def test_parse_number_stream_hex_and_bases():
    assert parse_number_stream("0x10 0o17 0b101") == [16, 15, 5]


def test_parse_number_stream_empty():
    assert parse_number_stream("") == []
    assert parse_number_stream("   ") == []


def test_intish_accepts_bases_and_separators():
    assert _intish("1_000") == 1000
    assert _intish("0xFF") == 255
    assert _intish("0b1010") == 10
    assert _intish("0o17") == 15
    assert _intish("1,234") == 1234


def test_intish_rejects_garbage():
    import argparse
    with pytest.raises(argparse.ArgumentTypeError):
        _intish("not-a-number")


# --------------------------------------------------------------------------- #
# end-to-end: capture from Python's random, predict a "token"
# --------------------------------------------------------------------------- #
def test_end_to_end_token_prediction():
    # Simulate a service issuing 32-bit "random" tokens from random.Random.
    service = random.Random("seed-material")
    observed = [service.getrandbits(32) for _ in range(_N)]
    attacker = mt19937_recover(observed)
    next_token = attacker.predict_next(1)[0]
    assert next_token == service.getrandbits(32)

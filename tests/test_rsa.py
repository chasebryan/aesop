"""
Correctness tests for aesop.modern.rsa — the textbook-RSA attack suite.

These check the *mathematics*, not merely that the code runs:
  * key-reconstruction / decryption round-trip identity,
  * that each solver recovers a KNOWN plaintext or key on a constructed case,
  * a classic literature vector (Wiener's original toy example),
  * edge cases: byte round-trips, non-coprime exponents, out-of-range messages,
    too-far-apart primes, missing-factor inputs.

Everything runs on deliberately tiny parameters so the whole file finishes in
well under ten seconds.
"""
from __future__ import annotations

import math

import pytest

from aesop.core.util import (
    bytes_to_int,
    is_probable_prime,
    int_to_bytes,
    isqrt,
)
from aesop.modern.rsa import (
    private_exponent,
    decrypt,
    message_bytes,
    reconstruct,
    factor_from_phi,
    factor_from_d,
    factor_small,
    fermat,
    pollard_pm1,
    pollard_rho,
    wiener,
    low_exponent,
    hastad_broadcast,
    common_modulus,
    common_factor,
)


# --------------------------------------------------------------------------- #
# helpers — build fresh demo keys deterministically, no sympy needed
# --------------------------------------------------------------------------- #
def next_prime(n: int) -> int:
    """Smallest prime strictly greater than ``n``."""
    n += 1
    if n <= 2:
        return 2
    if n % 2 == 0:
        n += 1
    while not is_probable_prime(n):
        n += 2
    return n


def make_key(p_seed: int, q_seed: int, e: int = 65537):
    """Return (n, e, d, p, q, phi) for primes just above the two seeds."""
    p = next_prime(p_seed)
    q = next_prime(q_seed)
    while q == p:
        q = next_prime(q)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = private_exponent(p, q, e)
    return n, e, d, p, q, phi


def encrypt(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


# A short plaintext used across the recovery tests.
MSG_BYTES = b"FOX"
MSG_INT = bytes_to_int(MSG_BYTES)


# --------------------------------------------------------------------------- #
# core primitives: key derivation + decryption round-trip
# --------------------------------------------------------------------------- #
def test_private_exponent_is_valid_inverse():
    n, e, d, p, q, phi = make_key(10**6 + 3, 10**6 + 500)
    # e*d ≡ 1 (mod λ(n)); check it decrypts every message.
    for m in (2, 123456, MSG_INT, n - 2):
        assert decrypt(encrypt(m, e, n), d, n) == m


def test_encrypt_decrypt_roundtrip_identity():
    n, e, d, *_ = make_key(50021, 60013)
    for m in range(0, 200):
        assert decrypt(encrypt(m, e, n), d, n) == m


def test_private_exponent_rejects_bad_exponent():
    # e sharing a factor with the totient has no inverse.
    p, q = 11, 23           # phi = 10*22 = 220 = 2^2·5·11
    with pytest.raises(ValueError):
        private_exponent(p, q, 2)   # gcd(2, 220) != 1


def test_message_bytes_roundtrip():
    for raw in (b"FOX", b"hello world", b"\x01\x02\x03", b"A"):
        m = bytes_to_int(raw)
        assert message_bytes(m) == raw


# --------------------------------------------------------------------------- #
# reconstruction (pure arithmetic, no search)
# --------------------------------------------------------------------------- #
def test_reconstruct_from_p_q_e_and_decrypt():
    n, e, d, p, q, phi = make_key(700001, 800011)
    c = encrypt(MSG_INT, e, n)
    res = reconstruct(p=p, q=q, e=e, c=c)
    assert res["n"] == n
    assert res["phi"] == phi
    assert res["d"] == d
    assert res["m"] == MSG_INT
    assert message_bytes(res["m"]) == MSG_BYTES


def test_reconstruct_from_n_phi_e():
    n, e, d, p, q, phi = make_key(120011, 130003)
    c = encrypt(MSG_INT, e, n)
    res = reconstruct(n=n, phi=phi, e=e, c=c)
    assert {res["p"], res["q"]} == {p, q}
    assert res["m"] == MSG_INT


def test_reconstruct_from_n_e_d():
    n, e, d, p, q, phi = make_key(140009, 150007)
    c = encrypt(MSG_INT, e, n)
    res = reconstruct(n=n, e=e, d=d, c=c)
    assert {res["p"], res["q"]} == {p, q}
    assert res["m"] == MSG_INT


def test_reconstruct_from_n_d_only_decrypts():
    n, e, d, *_ = make_key(160001, 170003)
    c = encrypt(MSG_INT, e, n)
    res = reconstruct(n=n, d=d, c=c)
    assert res["m"] == MSG_INT


# --------------------------------------------------------------------------- #
# factor recovery from leaked secrets
# --------------------------------------------------------------------------- #
def test_factor_from_phi():
    n, e, d, p, q, phi = make_key(300007, 400009)
    res = factor_from_phi(n, phi)
    assert res is not None
    assert res["p"] * res["q"] == n
    assert {res["p"], res["q"]} == {p, q}


def test_factor_from_phi_rejects_inconsistent():
    n, *_rest = make_key(300007, 400009)
    assert factor_from_phi(n, n - 12345) is None


def test_factor_from_d():
    n, e, d, p, q, phi = make_key(210011, 220009)
    res = factor_from_d(n, e, d)
    assert res is not None
    assert {res["p"], res["q"]} == {p, q}


# --------------------------------------------------------------------------- #
# factoring attacks
# --------------------------------------------------------------------------- #
def test_fermat_close_primes():
    p = next_prime(10**9)
    q = next_prime(p + 10)          # deliberately very close
    n = p * q
    res = fermat(n)
    assert res is not None
    assert {res["p"], res["q"]} == {p, q}
    assert res["p"] * res["q"] == n


def test_fermat_gives_up_on_far_primes():
    # A tiny iteration cap with far-apart primes must return None, not hang.
    p = next_prime(101)
    q = next_prime(10**7)
    n = p * q
    assert fermat(n, max_iters=50) is None


def test_fermat_end_to_end_decrypt():
    p = next_prime(10**9 + 7)
    q = next_prime(p + 100)
    n, e = p * q, 65537
    d = private_exponent(p, q, e)
    c = encrypt(MSG_INT, e, n)
    res = fermat(n)
    assert res is not None
    rec = reconstruct(n=n, e=e, p=res["p"], q=res["q"], c=c)
    assert rec["m"] == MSG_INT
    assert message_bytes(rec["m"]) == MSG_BYTES


def test_pollard_pm1_smooth():
    # Build p with a B-smooth p-1 (only tiny prime factors), q arbitrary.
    smooth = 1
    for pr in (2, 2, 2, 3, 3, 5, 7, 11, 13):
        smooth *= pr
    p = None
    base = smooth
    for _ in range(200):
        if is_probable_prime(base + 1):
            p = base + 1
            break
        base *= 2
    assert p is not None
    q = next_prime(10**6 + 33)
    n = p * q
    res = pollard_pm1(n, B=50)
    assert res is not None
    assert {res["p"], res["q"]} == {min(p, q), max(p, q)}


def test_pollard_rho_small_factor():
    p = next_prime(3000)            # small factor rho clears quickly
    q = next_prime(10**9 + 9)
    n = p * q
    res = pollard_rho(n)
    assert res is not None
    assert res["p"] * res["q"] == n
    assert p in (res["p"], res["q"])


def test_factor_small_trial_division():
    p = 101
    q = next_prime(10**7)
    n = p * q
    res = factor_small(n)
    assert res is not None
    assert p in (res["p"], res["q"])
    assert res["p"] * res["q"] == n


# --------------------------------------------------------------------------- #
# protocol / usage attacks
# --------------------------------------------------------------------------- #
def test_wiener_recovers_small_d():
    # Construct a key with a deliberately tiny private exponent.
    # Big enough primes that the Wiener bound (n^0.25/3) comfortably exceeds d.
    p = next_prime(10**12 + 7)
    q = next_prime(10**12 + 500)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = 65537                       # prime, well under n^0.25/3 (~3.3e5)
    assert math.gcd(d, phi) == 1
    assert d < isqrt(isqrt(n)) // 3
    e = pow(d, -1, phi)
    res = wiener(n, e)
    assert res is not None
    assert res["d"] == d
    assert {res["p"], res["q"]} == {p, q}
    # and the recovered d actually decrypts
    c = encrypt(MSG_INT, e, n)
    assert decrypt(c, res["d"], n) == MSG_INT


def test_wiener_literature_vector():
    # Wiener's classic small example (Boneh's survey): n=90581, e=17993, d=5.
    res = wiener(90581, 17993)
    assert res is not None
    assert res["d"] == 5
    assert res["p"] * res["q"] == 90581


def test_wiener_fails_when_d_large():
    n, e, d, *_ = make_key(10**6 + 3, 10**6 + 500)  # normal e=65537, big d
    assert wiener(n, e) is None


def test_low_exponent_cube_root():
    # m^3 < n so the ciphertext is a perfect cube.
    m = MSG_INT
    e = 3
    n = next_prime(m**3 + 12345) * next_prime(10**3)  # ensure n > m^e comfortably
    n = next_prime(m**e + 10**9) * next_prime(10**9)
    c = encrypt(m, e, n)
    assert m**e < n
    res = low_exponent(c, e, n)
    assert res is not None
    assert res["m"] == m
    assert message_bytes(res["m"]) == MSG_BYTES


def test_low_exponent_fails_when_message_wraps():
    # A message large enough that m^e >> n and does not wrap cleanly.
    p = next_prime(10**5 + 3)
    q = next_prime(10**5 + 19)
    n = p * q
    m = n - 3                       # huge relative to n; m^3 wraps many times
    c = encrypt(m, 3, n)
    # With the default small wrap budget this must not report a false root.
    res = low_exponent(c, 3, n, tries=5)
    assert res is None or res["m"] == m


def test_hastad_broadcast_e3():
    m = MSG_INT
    e = 3
    ns, cs = [], []
    seed = 10**7
    while len(ns) < e:
        p = next_prime(seed)
        q = next_prime(p + 5000)
        n = p * q
        seed = q + 1000
        if any(math.gcd(n, prev) != 1 for prev in ns):
            continue
        ns.append(n)
        cs.append(encrypt(m, e, n))
    res = hastad_broadcast(cs, ns, e)
    assert res is not None
    assert res["m"] == m
    assert message_bytes(res["m"]) == MSG_BYTES


def test_hastad_needs_enough_pairs():
    assert hastad_broadcast([1, 2], [3, 5], 3) is None


def test_common_modulus():
    n, e_unused, d, p, q, phi = make_key(10**6 + 3, 10**6 + 33)
    m = MSG_INT
    e1, e2 = 17, 65537
    assert math.gcd(e1, e2) == 1
    c1 = encrypt(m, e1, n)
    c2 = encrypt(m, e2, n)
    res = common_modulus(c1, e1, c2, e2, n)
    assert res is not None
    assert res["m"] == m
    assert message_bytes(res["m"]) == MSG_BYTES


def test_common_modulus_non_coprime_exponents():
    n, *_ = make_key(10**6 + 3, 10**6 + 33)
    assert common_modulus(2, 4, 8, 6, n) is None   # gcd(4,6)=2


def test_common_factor_shared_prime():
    shared = next_prime(10**9 + 7)
    q1 = next_prime(10**9 + 100)
    q2 = next_prime(10**9 + 500)
    n1 = shared * q1
    n2 = shared * q2
    n3 = next_prime(10**8) * next_prime(10**8 + 3)   # coprime to the others
    res = common_factor([n1, n2, n3])
    assert res is not None
    # both n1 and n2 must be cracked, revealing the shared prime
    assert 0 in res["keys"] and 1 in res["keys"]
    assert res["keys"][0]["p"] in (shared, q1)
    assert res["keys"][0]["p"] * res["keys"][0]["q"] == n1
    assert res["keys"][1]["p"] * res["keys"][1]["q"] == n2
    assert any(s["p"] == shared for s in res["shared"])


def test_common_factor_all_coprime():
    a = next_prime(10**6) * next_prime(10**6 + 100)
    b = next_prime(10**6 + 200) * next_prime(10**6 + 300)
    assert common_factor([a, b]) is None


# --------------------------------------------------------------------------- #
# edge cases
# --------------------------------------------------------------------------- #
def test_int_to_bytes_preserves_ascii():
    for text in (b"FOX", b"the quick brown fox"):
        assert int_to_bytes(bytes_to_int(text)) == text


def test_fermat_rejects_even():
    assert fermat(0) is None
    assert fermat(100) is None


def test_factor_small_none_on_semiprime_of_large_primes():
    # Two large balanced primes (n > 110 bits, so the sympy path is skipped and
    # trial division alone cannot peel a factor).
    p = next_prime(10**17 + 39)
    q = next_prime(10**17 + 61)
    n = p * q
    assert n.bit_length() > 110
    res = factor_small(n, trial_bound=1000)
    assert res is None

"""
Correctness tests for aesop.encoding.bases.

These check that the codecs are actually *correct* — known-answer tests against
the literature, round-trip identity over the full byte range, and the lenient
edge cases the module documents — not merely that they run.
"""
import base64

import pytest

from aesop.encoding.bases import (
    b64_encode, b64_decode,
    b32_encode, b32_decode,
    b58_encode, b58_decode,
    b85_encode, b85_decode,
    hex_encode, hex_decode,
    binary_encode, binary_decode,
    url_encode, url_decode,
    B58_ALPHABET,
)

MSG = b"Hello, AESOP!"
ALL_BYTES = bytes(range(256))


# --------------------------------------------------------------------------- #
# Round-trip identity: decode(encode(x)) == x
# --------------------------------------------------------------------------- #
ROUND_TRIPS = {
    "b64": (b64_encode, b64_decode),
    "b64url": (lambda d: b64_encode(d, url=True), lambda s: b64_decode(s, url=True)),
    "b32": (b32_encode, b32_decode),
    "b58": (b58_encode, b58_decode),
    "b85": (b85_encode, b85_decode),
    "ascii85": (lambda d: b85_encode(d, ascii85=True), lambda s: b85_decode(s, ascii85=True)),
    "hex": (hex_encode, hex_decode),
    "binary": (binary_encode, binary_decode),
    "binary_packed": (lambda d: binary_encode(d, packed=True), binary_decode),
    "url": (url_encode, url_decode),
}


@pytest.mark.parametrize("name", sorted(ROUND_TRIPS))
@pytest.mark.parametrize("data", [b"", b"\x00", b"x", MSG, b"\x00\x00hello", ALL_BYTES,
                                  bytes(range(1, 40)), b"\xff\xff\xff\xff"])
def test_round_trip(name, data):
    enc, dec = ROUND_TRIPS[name]
    assert dec(enc(data)) == data


@pytest.mark.parametrize("name", sorted(ROUND_TRIPS))
def test_encoding_is_ascii_str(name):
    enc, _ = ROUND_TRIPS[name]
    out = enc(MSG)
    assert isinstance(out, str)
    out.encode("ascii")  # must be pure ASCII


# --------------------------------------------------------------------------- #
# Known-answer tests (values from the standards / reference implementations)
# --------------------------------------------------------------------------- #
def test_kat_base64():
    assert b64_encode(b"Hello, AESOP!") == "SGVsbG8sIEFFU09QIQ=="
    # RFC 4648 test vectors
    assert b64_encode(b"") == ""
    assert b64_encode(b"f") == "Zg=="
    assert b64_encode(b"fo") == "Zm8="
    assert b64_encode(b"foo") == "Zm9v"
    assert b64_encode(b"foob") == "Zm9vYg=="
    assert b64_encode(b"fooba") == "Zm9vYmE="
    assert b64_encode(b"foobar") == "Zm9vYmFy"


def test_kat_base64_url():
    # bytes chosen to produce + and / in standard, - and _ in url-safe
    data = b"\xfb\xff\xbf"
    assert b64_encode(data) == "+/+/"
    assert b64_encode(data, url=True) == "-_-_"


def test_kat_base32():
    # RFC 4648 test vectors
    assert b32_encode(b"") == ""
    assert b32_encode(b"f") == "MY======"
    assert b32_encode(b"fo") == "MZXQ===="
    assert b32_encode(b"foo") == "MZXW6==="
    assert b32_encode(b"foob") == "MZXW6YQ="
    assert b32_encode(b"fooba") == "MZXW6YTB"
    assert b32_encode(b"foobar") == "MZXW6YTBOI======"
    assert b32_encode(b"hello") == "NBSWY3DP"


def test_kat_base58():
    # Bitcoin base58 reference values
    assert b58_encode(b"hello") == "Cn8eVZg"
    assert b58_encode(b"") == ""
    # leading zero bytes -> leading '1's, one per zero byte
    assert b58_encode(b"\x00\x00hello") == "11Cn8eVZg"
    assert b58_encode(b"\x00") == "1"
    assert b58_encode(b"\x00\x00\x00") == "111"


def test_kat_hex():
    assert hex_encode(b"Hello") == "48656c6c6f"
    assert hex_encode(bytes([0, 255, 16])) == "00ff10"
    assert hex_encode(b"") == ""


def test_kat_binary():
    assert binary_encode(b"Hi") == "01001000 01101001"
    assert binary_encode(b"Hi", packed=True) == "0100100001101001"
    assert binary_encode(b"\x00") == "00000000"
    assert binary_encode(b"\xff") == "11111111"


def test_kat_url():
    assert url_encode(b"a b&c=d") == "a%20b%26c%3Dd"
    # unreserved set is passed through untouched
    assert url_encode(b"AZaz09-_.~") == "AZaz09-_.~"


def test_kat_ascii85_vs_rfc1924():
    # The two Base85 variants must differ and both round-trip.
    data = b"Hello, AESOP!"
    rfc = b85_encode(data)
    adobe = b85_encode(data, ascii85=True)
    assert rfc == base64.b85encode(data).decode()
    assert adobe == base64.a85encode(data).decode()
    assert b85_decode(rfc) == data
    assert b85_decode(adobe, ascii85=True) == data


# --------------------------------------------------------------------------- #
# Base58 alphabet integrity (no confusable glyphs, length 58)
# --------------------------------------------------------------------------- #
def test_base58_alphabet():
    assert len(B58_ALPHABET) == 58
    assert len(set(B58_ALPHABET)) == 58
    for bad in "0OIl":
        assert bad not in B58_ALPHABET


# --------------------------------------------------------------------------- #
# Lenient decoding — the documented forgiving behaviour
# --------------------------------------------------------------------------- #
def test_b64_decode_missing_padding():
    assert b64_decode("SGVsbG8") == b"Hello"       # would need '=' padding
    assert b64_decode("SGVsbG8=") == b"Hello"


def test_b64_decode_accepts_urlsafe_alphabet():
    data = b"\xfb\xff\xfe\x10"
    std = base64.b64encode(data).decode()
    url = base64.urlsafe_b64encode(data).decode()
    assert b64_decode(std) == data
    assert b64_decode(url) == data                  # normalises -/_ to +//


def test_b64_decode_strips_whitespace():
    assert b64_decode("SGVs\nbG8s\n IEFF U09QIQ==") == b"Hello, AESOP!"
    assert b64_decode("  SGVsbG8=  ") == b"Hello"


def test_b32_decode_case_insensitive():
    enc = b32_encode(b"hello")
    assert b32_decode(enc.lower()) == b"hello"
    assert b32_decode(enc.upper()) == b"hello"


def test_hex_decode_separators_and_prefix():
    assert hex_decode("de:ad:be:ef") == b"\xde\xad\xbe\xef"
    assert hex_decode("de-ad-be-ef") == b"\xde\xad\xbe\xef"
    assert hex_decode("de ad be ef") == b"\xde\xad\xbe\xef"
    assert hex_decode("0x48656c6c6f") == b"Hello"
    assert hex_decode("48,65,6c") == b"Hel"


def test_hex_decode_odd_length_raises():
    with pytest.raises(ValueError):
        hex_decode("abc")


def test_binary_decode_ignores_non_bits():
    assert binary_decode("01001000 01101001") == b"Hi"
    assert binary_decode("01001000,01101001") == b"Hi"
    assert binary_decode("0100100001101001") == b"Hi"
    # short run left-padded to a whole byte
    assert binary_decode("101") == bytes([0b00000101])


def test_b58_decode_invalid_char_raises():
    with pytest.raises(ValueError):
        b58_decode("hello0world")   # '0' is not in the base58 alphabet


def test_url_decode_returns_raw_bytes():
    assert url_decode("a%20b%26c%3Dd") == b"a b&c=d"
    # percent-encoded arbitrary byte
    assert url_decode("%00%ff") == b"\x00\xff"


# --------------------------------------------------------------------------- #
# Base58 leading-zero preservation is exact (property test)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("nzeros", [0, 1, 2, 5])
def test_b58_leading_zero_count(nzeros):
    data = b"\x00" * nzeros + b"payload"
    enc = b58_encode(data)
    assert enc.startswith("1" * nzeros)
    if nzeros == 0:
        assert not enc.startswith("1")
    assert b58_decode(enc) == data


# --------------------------------------------------------------------------- #
# Encode output shape guarantees
# --------------------------------------------------------------------------- #
def test_hex_is_lowercase_two_per_byte():
    out = hex_encode(bytes(range(256)))
    assert out == out.lower()
    assert len(out) == 512


def test_binary_length_multiple_of_8():
    assert len(binary_encode(b"abc", packed=True)) == 24

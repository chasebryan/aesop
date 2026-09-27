# Entropy — the tell-tale heart of hidden data
> Encryption and compression flatten bytes until they look like pure noise. `entropy` measures that noise — overall and in a moving window — to tell random from structured.

## The fable

The wolf in sheep's clothing still moves like a wolf. Ciphertext dressed up as an
innocent file still *behaves* like randomness — and randomness has a number.
`entropy` reads that number, so a payload trying to look like nothing at all gives
itself away.

## What entropy measures

Shannon entropy is the average number of bits needed to encode each symbol, given
how often each one appears. For bytes it runs from 0 to 8:

```
≈ 8.0   every byte value roughly equally likely  → encrypted / compressed / random
6–7.5   packed, encoded, or high-variety binary
4–4.5   English text (a-z, space dominate)
< 2     highly structured / repetitive (runs, padding, sparse formats)
```

A high, flat entropy is the classic signature of good encryption or compression:
there is no statistical handle to grab, which is exactly why you should stop
trying frequency attacks and start thinking about keys, XOR, or block structure.

## Why a sliding window matters

A single number for the whole file hides *where* the structure is. Real artefacts
are often mixed: a low-entropy header or magic bytes, then a high-entropy
encrypted body; or plaintext padding around a compressed blob. `entropy` walks a
window across the data and reports the min, the max, and *where* each occurs, plus
a one-line ASCII sparkline of the whole trace:

```console
$ head -c 4096 /dev/urandom | aesop entropy
7.95
▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇
sliding-window entropy
  overall entropy  7.95 bits/byte  (random / encrypted / compressed)
  minimum          7.03 at offset 2304
  maximum          7.27 at offset 384
```

A dip in the sparkline points you straight at a structured region worth carving
out and examining on its own.

## Byte distribution

Alongside entropy, `entropy` summarises *which kind* of bytes you have —
printable (0x20–0x7e), high-bit (≥0x80), control, and null — and how many of the
256 possible values actually appear. Encrypted data uses nearly all 256 fairly
evenly; text clusters in the printable range; a format with lots of zeros betrays
padding or fixed-width fields.

## Reading raw bytes vs decoding first

By default `entropy` measures the **raw bytes** exactly as given (over stdin and
files it never re-encodes them, so high bytes stay intact). If your input is a hex
or base64 *wrapper* around the real payload, pass `-e hex` / `-e base64` to decode
first and measure the entropy of the payload itself — a base64 string looks
lower-entropy than the bytes it encodes, because it only uses 64 symbols.

## Using AESOP

```console
# Is this random/encrypted? (expect ≈ 8.0)
$ head -c 4096 /dev/urandom | aesop entropy

# A suspicious file
$ aesop entropy -f suspicious.bin

# English text scores low
$ echo 'the quick brown fox' | aesop entropy

# Tune the window to zoom in on structure
$ aesop entropy -w 32 -f firmware.bin

# Measure the decoded payload, not the base64 wrapper
$ aesop entropy -e base64 <blob>
```

The first line printed is the overall entropy value on its own (pipe-friendly);
the sparkline, window stats and byte summary follow.

### Options

| flag | meaning |
|------|---------|
| `-w, --window N` | Sliding-window size in bytes (default: auto, ~16–256). |
| `-s, --step N` | Window step in bytes (default: window / 2). |
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Decode as `hex`/`base64`/… before measuring (default: raw bytes). |

## When to reach for it

- Triaging an unknown file: random-looking, or is there structure to attack?
- Confirming something is encrypted/compressed before you stop doing frequency
  analysis on it.
- Locating a boundary between a plaintext header and an encrypted body.
- Sanity-checking that "random" output really is high-entropy.

Small inputs give shaky numbers — a 16-byte window can hold at most 16 distinct
values, so its entropy caps well below 8 even for true randomness. Read the
*trend* and the *contrast between regions*, not a single tiny window.

## See also

- `aesop manual identify` — entropy is one of the signals it uses; start there.
- `aesop manual frequency` — the letter-level statistics for *low*-entropy text.
- `aesop manual xor` — a common next step once data looks encrypted.
- `aesop manual scoring` — entropy alongside IC, chi-squared and quadgrams.

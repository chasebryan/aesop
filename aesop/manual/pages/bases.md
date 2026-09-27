# Bases & Encodings — Base64/32/58/85, Hex, Binary, URL
> Not ciphers, just costumes. Every one of these wraps the same bytes in a different skin — and every skin peels off with a single flag.

## The fable

In *The Fox and the Grapes* the fox is defeated by appearances: the grapes only
*look* out of reach. Encodings are the same trick played on data. A blob of
Base64 or hex looks like nonsense, but there is no secret inside — no key, no
work factor, nothing to break. You just have to recognise the skin and strip it.
These commands are the fox learning that the grapes were never really that high.

## What these are (and are not)

An **encoding** is a reversible, keyless mapping between bytes and a restricted
character set. It provides **no confidentiality** — anyone can decode it. Its job
is transport: squeezing binary through channels that only accept text (email,
URLs, JSON, QR codes, config files).

If a value has an index of coincidence, letter frequencies, or a repeating
structure, it may be a *cipher* — reach for `aesop identify`. If it is just a run
of `A–Za–z0–9+/=` or `0–9a–f`, it is almost certainly one of the encodings below.
When several are stacked, let `aesop magic` peel them for you.

## The codecs

### Base64 — `aesop b64`
Three bytes → four characters over `A–Z a–z 0–9 + /`, padded with `=`. The most
common binary-in-text encoding on earth. `--url` swaps `+/` for `-_` (safe in
URLs and filenames). Decoding accepts either alphabet and repairs missing padding.

```
Hello, AESOP!  ->  SGVsbG8sIEFFU09QIQ==
```

### Base32 — `aesop b32`
Five bytes → eight characters over `A–Z 2–7`. Bigger than Base64 but
case-insensitive and hard to mis-transcribe, so it shows up in TOTP/2FA secrets
and Tor v3 onion addresses.

```
hello  ->  NBSWY3DP
```

### Base58 — `aesop b58`
Base62 with the confusable glyphs removed (`0`, `O`, `I`, `l`). It is a straight
big-integer conversion, not a block encoding, so there is no padding — instead
**each leading `0x00` byte is written as a leading `1`**. This is the encoding of
Bitcoin addresses, WIF keys and IPFS CIDs. AESOP implements it with no external
dependency.

```
b"\x00\x00hello"  ->  11 + base58("hello")   # two zero bytes -> two leading 1s
```

### Base85 / ASCII85 — `aesop b85`
Four bytes → five characters, denser than Base64. The default alphabet is
**RFC 1924** (the one used by Git binary diffs and Python's `base64.b85`).
`--ascii85` selects the **Adobe/PostScript ASCII85** variant instead.

```
Hello, AESOP!  ->  NM&qnZ!91|MN>~uAp     (RFC 1924)
```

### Hex — `aesop hex`
Two lower-case characters per byte, no separators on encode. Decoding is
forgiving: whitespace, `:`/`-`/`,` separators and a leading `0x` are all stripped
first, so a hexdump pasted from Wireshark, `xxd` or a debugger round-trips.

```
Hello  ->  48656c6c6f
de:ad:be:ef  ->  (decodes fine)
```

### Binary — `aesop binary`
Each byte as eight `0`/`1` bits. Bytes are space-separated by default for
readability; `--packed` removes the spaces. On decode, everything that is not a
`0` or `1` is ignored (so spaced, packed and comma-separated strings all work),
and a partial run is left-padded to a whole byte.

```
Hi  ->  01001000 01101001
```

### URL — `aesop url`
RFC 3986 percent-encoding: every byte outside the unreserved set
(`A–Z a–z 0–9 - _ . ~`) becomes `%XX`. Safe for binary; decoding reverses any
`%XX` escape and returns raw bytes.

```
a b&c=d  ->  a%20b%26c%3Dd
```

## Using AESOP

Every command **encodes by default** and **decodes with `-d`**. Input can be a
literal argument, a file (`-f`), or a pipe. The result is written with `out.raw`,
so everything composes:

```console
# Encode a literal
$ aesop b64 'Hello, AESOP!'
SGVsbG8sIEFFU09QIQ==

# Decode it back
$ aesop b64 -d 'SGVsbG8sIEFFU09QIQ=='
Hello, AESOP!

# Pipe two codecs together — the classic round-trip test
$ echo 'Attack at dawn' | aesop b64 | aesop b64 -d
Attack at dawn

# Encode a binary file (URL-safe alphabet)
$ aesop b64 --url -f photo.png

# Chain across encodings
$ aesop hex 'secret' | aesop hex -d | aesop b58
```

When the decoded bytes are not printable text, AESOP prints them as **hex** so
your terminal stays sane; pipe to `-f`/a file or on to another decoder to keep
the raw bytes.

### Options

| flag | applies to | meaning |
|------|------------|---------|
| `-d, --decode` | all | Decode instead of encode. |
| `--url` | `b64` | Use the URL-safe alphabet (`-`/`_`). |
| `-a, --ascii85` | `b85` | Use Adobe ASCII85 instead of RFC-1924 Base85. |
| `--packed` | `binary` | Emit bits with no spaces between bytes. |
| `-f, --file` | all | Read input from a file. |
| `-e, --in-encoding` | all | Force `raw`/`hex`/`base64` input decoding. |

### Aliases

`b64`=`base64`, `b32`=`base32`, `b58`=`base58`, `b85`=`base85`/`ascii85`,
`hex`=`tohex`, `binary`=`bits`, `url`=`percent`.

## When to reach for it

- The data is a solid run of a single restricted alphabet with no word
  boundaries: `A–Za–z0–9+/=` (Base64), `A–Z2–7=` (Base32), `0–9a–f` (hex),
  `01` (binary), or `%XX` escapes (URL).
- A challenge, config value or token *looks* random but has **length that is a
  multiple of 4** (Base64/85) or **8** (Base32/binary) — a strong tell of an
  encoding rather than a cipher.
- A value starts with `1` and avoids `0OIl` — suspect a Base58 address.
- You need to feed binary through something text-only, or reverse that.

If a value survives decoding but still looks scrambled, it was probably
**encrypted, not just encoded** — hand the result to `aesop identify` or
`aesop auto`.

## See also

- `aesop manual magic` — auto-detect and peel *stacked* encodings in one shot.
- `aesop manual auto` — the full triage-and-solve pipeline.
- `aesop manual xor` — the simplest thing that *is* actually a cipher.
- `aesop manual scoring` — how AESOP decides text "looks like English".

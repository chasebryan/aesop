# Magic — Automatic Multi-Layer Decoding
> Peels nested encodings for you, like unwrapping a matryoshka, and stops the moment a flag falls out.

## The fable

*The Fox and the Grapes* teaches persistence against a stubborn prize. `magic`
is that persistence automated: it keeps trying decodings, following the most
promising branch, until the hidden text is in reach.

## What it does

Many puzzles wrap a payload in several reversible layers — say
`ROT13( base64( hex( gzip( "flag{…}" ) ) ) )`. Undoing them by hand is tedious
and easy to get out of order. `magic` searches the space of decodings for you.

At each step it tries every reversible operation it knows:

| category | operations |
|----------|-----------|
| bases | base64, base64url, base32, base85/ascii85, hex, binary, decimal-bytes |
| web | URL / percent-decoding |
| compression | gzip, zlib/deflate |
| classical | ROT13, best-scoring Caesar shift, reverse |

It scores each result by how readable it looks (printable ratio + English
model), pursues the best branches first (a best-first search), and **halts
immediately** when a result matches the flag pattern. The winning sequence is
printed as a **recipe** so you can reproduce or explain it.

## Using AESOP

```console
# Single hidden layer
$ aesop magic 'NBSWY3DPEB3W64TMMQ======'
✓ best result via: from-base32
hello world

# Nested: it finds the whole chain
$ echo 'ZmxhZ3tuZXN0ZWR9' | aesop magic
✓ flag found via: from-base64
flag{nested}

# Search deeper, with a custom flag format, from a file
$ aesop magic --depth 8 --flag-format 'CTF\{.*\}' -f blob.txt
```

### Options

| flag | meaning |
|------|---------|
| `--depth N` | Maximum number of stacked operations to try (default 6). |
| `--flag-format REGEX` | Pattern that marks success and stops the search. Default matches `word{...}`. |
| `--no-flag` | Don't stop on a flag; just rank everything by readability. |
| `--top K` | Show the K best candidate recipes (default 5). |
| `-f, --file` | Read the blob from a file. |

## When to reach for it

- You have a blob and don't know how many layers of encoding wrap it.
- A CTF challenge gives an opaque string and hints "decode me".
- Use it **before** `aesop identify` for a fast "just try everything" pass; use
  `identify` when you want a reasoned single hypothesis instead of a search.

`magic` handles *encodings and compression*, not *ciphers with keys*. If the
payload is enciphered (XOR, Vigenère, substitution, RSA…), decode the outer
layers with `magic`, then hand the core to the matching solver — or let
`aesop auto` orchestrate both.

## See also

- `aesop manual auto` — the full auto-solver that also breaks keyed ciphers.
- `aesop manual identify` — reasoned single-hypothesis triage.
- `aesop manual bases` — the individual codecs, driven manually.

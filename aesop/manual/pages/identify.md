# Identify — fingerprinting an unknown blob
> "Know thine enemy." Before you can break a cipher, you have to guess *which* cipher. `identify` fingerprints the input and tells you what to try next.

## The fable

The fox in Aesop's tales survives by reading the situation before it acts — a
lion's paw-print, a trap's tell-tale bait. `identify` is that first glance: it
does not break anything, it tells you *what you are holding* so you don't waste
moves brute-forcing a hash or feeding base64 to a Caesar solver.

## What it does

`identify` runs your input past a battery of signatures and prints ranked
hypotheses, each with a confidence, a plain-English reason, and the exact AESOP
command to try next. The signals it weighs:

- **Character set & structure** — is it all hex digits? A base64/base32/URL-safe
  alphabet? Only Morse dots and dashes?
- **Length fingerprints** — 32/40/64/128 hex chars are classic digest lengths
  (MD5, SHA-1, SHA-256, SHA-512).
- **Shannon entropy** — near 8 bits/byte with low printable ratio ⇒ encrypted or
  compressed; see `aesop manual entropy`.
- **Index of coincidence** — ~0.066 ⇒ monoalphabetic (Caesar / substitution /
  plaintext); ~0.04 ⇒ polyalphabetic (Vigenère); see `aesop manual frequency`.
- **Chi-squared** against English — separates plaintext/Caesar from a general
  substitution that has remapped the letters.

The same reasoning powers `aesop auto`, which then *runs* the most likely attack
for you.

## It reads the input literally

This is deliberate and important: `identify` does **not** silently decode
base64/hex first. If it did, `identify 'V2FrZSB1cA=='` would decode to `Wake up`
and report "plaintext" — hiding the very fact you wanted to learn. So it analyses
exactly the bytes you hand over. Pass `-e hex`/`-e base64` if you *do* want it to
decode first and fingerprint the decoded payload.

## Using AESOP

```console
# A mystery token — encoding? hash? cipher?
$ aesop identify 'V2FrZSB1cCwgTmVvIQ=='

# Pipe ciphertext straight in
$ echo 'Wkh txlfn eurzq ira' | aesop identify

# A file (text or binary)
$ aesop identify -f mystery.bin

# 32 hex chars — probably a digest
$ aesop identify 5d41402abc4b2a76b9719d911017c592

# Fingerprint the *decoded* payload instead of the base64 wrapper
$ aesop identify -e base64 'V2FrZSB1cCwgTmVvIQ=='
```

The first line printed is the single best-guess label (so `identify … | …` is
pipe-friendly); the ranked table and an input-stats panel follow.

### Options

| flag | meaning |
|------|---------|
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Decode as `hex`/`base64`/… *before* fingerprinting (default: analyse raw). |

### Reading the output

- **conf** is a rough confidence, not a probability — treat the *ranking* as the
  signal, and try the top one or two suggestions.
- The **input stats** panel (length, printable %, entropy, IC) is the same set of
  numbers a human cryptanalyst eyeballs first; they explain *why* each guess was
  made.

## When to reach for it

- You have a blob and no idea what it is — this is always the first command.
- A challenge gives you a token with no context.
- Something decoded to more gibberish and you want to know what layer you're on.

Short inputs (a dozen letters or fewer) don't carry enough statistical signal, so
IC/entropy-based guesses get shaky — trust the character-set and length signals
there, and lean on `aesop freq` once you have more text.

## See also

- `aesop manual frequency` — the letter statistics behind the classical guesses.
- `aesop manual entropy` — the randomness measure behind "encrypted/compressed".
- `aesop manual auto` — take the top guess and actually run the attack.
- `aesop manual getting-started` — the whole triage-then-attack workflow.

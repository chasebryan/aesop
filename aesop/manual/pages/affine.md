# The Affine Cipher
> Caesar learns to multiply. Each letter is scaled and then shifted — still one fixed alphabet, still broken by trying every key.

## The fable

In *The Fox and the Grapes*, the fox dresses up his failure as a choice: the
grapes were surely sour anyway. The Affine cipher dresses up Caesar the same
way — the extra multiplication *looks* like more security, but with only 312
possible keys the disguise is just as thin. The fox tries them all.

## How it works

Number the letters A=0, B=1, …, Z=25. Pick two key numbers:

- a **multiplier** `a`, which must be **coprime with 26**, and
- an **additive shift** `b`, any value 0–25.

Encryption of a plaintext letter *x* is:

```
c = (a·x + b) mod 26
```

Decryption reverses it with the modular inverse of `a`:

```
x = a⁻¹·(c − b) mod 26
```

`a⁻¹` is the number with `a·a⁻¹ ≡ 1 (mod 26)` — AESOP computes it with the
extended Euclidean algorithm (`aesop.core.util.modinv`).

### Why `a` must be coprime with 26

If `a` shares a factor with 26 (= 2 · 13) the map collapses: several plaintext
letters land on the same ciphertext letter and it can no longer be undone. Only
these **12 multipliers** are legal:

```
1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
```

Two familiar ciphers are special cases: `a = 1` is a plain **Caesar** shift of
`b`, and `a = 25, b = 25` is **Atbash** (the alphabet reversed).

## Breaking it

The keyspace is `12 × 26 = 312` keys (311 if you drop the identity `a=1, b=0`),
so brute force is instant. Two complementary strategies, both built in:

1. **Brute force + language scoring.** Decrypt under all 312 keys, score each
   result with an English model, and rank. AESOP uses **quadgram
   log-probabilities** (see `aesop manual scoring`), which reliably float the
   true plaintext — and its `(a, b)` — to the top for any text of ~12+ letters.
2. **Chi-squared frequency matching.** Compare each candidate's letter-frequency
   profile to English and keep the closest. This needs no full-language model;
   reach for it (via `--chi2`) on very short ciphertext, though with only a
   dozen letters any statistic is shaky.

Because the multiplication permutes letters non-uniformly, a Caesar solver will
**not** break an Affine cipher with `a ≠ 1` — you need the multiplier in the
search, which is exactly what `aesop affine` does.

## Using AESOP

```console
# Auto-solve (no key needed): ranks all 312 keys, prints the best plaintext
$ aesop affine 'Izzisg iz xiov, zrc hat wu oizsrwvm zrc spao.'

# Encode with a known key (Wikipedia's classic a=5, b=8)
$ aesop affine --encode -a 5 -b 8 'Attack at dawn'

# Decode with a known key
$ aesop affine -a 5 -b 8 'Izzisg iz xiov'

# Short ciphertext: switch the fitness function to chi-squared
$ aesop affine --chi2 'Izzisg iz xiov'

# Works with pipes and files too
$ echo 'Izzisg iz xiov' | aesop affine
$ aesop affine -f ciphertext.txt
```

### Options

| flag | meaning |
|------|---------|
| `-a A` | Known multiplier (must be coprime with 26). |
| `-b B` | Known additive shift (0–25). |
| `--encode` | Encrypt with `-a`/`-b` instead of breaking. |
| `--chi2` | Auto-solve short text by frequency matching, not quadgrams. |
| `--top K` | Show the top *K* candidates when auto-solving (default 3). |
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Force `raw`/`hex`/`base64` input decoding. |

If you give `-a`/`-b` without `--encode`, AESOP **decodes** with that key; add
`--encode` to go the other way. Omitting a part while encoding falls back to the
textbook `a=5, b=8`.

## When to reach for it

- The ciphertext is alphabetic, roughly the length of the plaintext, and
  preserves word boundaries.
- The **Index of Coincidence** (`aesop freq`) is near **0.066** (English-like),
  indicating a *monoalphabetic* cipher rather than a polyalphabetic one …
- … but a plain **Caesar** solve (`aesop caesar`) fails. That mismatch — English
  IC yet no single shift works — is the classic fingerprint of an Affine key
  with `a ≠ 1`.

If `aesop affine` also fails on English-like IC, the cipher is a **general
monoalphabetic substitution** (`aesop substitution`) rather than an affine map.
If the IC is low (~0.04), suspect **Vigenère** (`aesop vigenere`) or another
polyalphabetic scheme.

## See also

- `aesop manual caesar` — the `a = 1` special case (shift only).
- `aesop manual substitution` — when the alphabet is remapped arbitrarily.
- `aesop manual misc` — Atbash (`a = 25, b = 25`) and other fixed alphabets.
- `aesop manual scoring` — how "looks like English" is measured.

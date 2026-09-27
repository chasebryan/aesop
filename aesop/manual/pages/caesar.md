# Caesar & ROT-n Shift Ciphers
> Every letter marches the same number of steps down the alphabet. The oldest trick in the book — and the easiest to break.

## The fable

In the fable of *The Fox and the Crow*, the crow is fooled because it cannot see
the flattery for what it is. A Caesar cipher fools no one for long: there are
only 25 disguises, and the fox tries them all.

## How it works

Pick a shift `k` (1–25). Encryption replaces each plaintext letter *p* with:

```
c = (p + k) mod 26
```

Decryption is the reverse, `p = (c − k) mod 26`. **ROT13** is simply `k = 13`,
which is its own inverse (applying it twice returns the original). **Atbash** is
a related fixed substitution (`c = 25 − p`) — see `aesop manual misc`.

Because the key is one of only 26 values (25 useful ones), the cipher offers no
real security. It is important historically and appears constantly in CTFs as a
first or last layer.

## Breaking it

Two complementary strategies, both built in:

1. **Brute force + language scoring.** Try all 26 shifts, score each result
   with an English model, and rank. AESOP uses **quadgram log-probabilities**
   (see `aesop manual scoring`), which reliably float the true plaintext to the
   top for any text of ~12+ letters.
2. **Chi-squared frequency matching.** Compare each shift's letter-frequency
   profile to English. This needs no full plaintext model and shines on very
   short ciphertext. AESOP falls back to it internally when text is tiny.

## Using AESOP

```console
# Auto-solve (no key needed): ranks all shifts, prints the best plaintext
$ aesop caesar 'Wkh txlfn eurzq ira'

# See the whole ROT table, best-scoring first
$ aesop caesar --all 'Uryyb Jbeyq'

# Apply a known shift (encoding). ROT13:
$ aesop caesar --encode -n 13 'Attack at dawn'

# Decode with a known shift
$ aesop caesar -n 23 'Wkh txlfn eurzq ira'

# Works with pipes and files too
$ echo 'Fdhvdu flskhu' | aesop caesar
$ aesop caesar -f ciphertext.txt
```

### Options

| flag | meaning |
|------|---------|
| `-n, --shift N` | Known shift; applies the transform directly. |
| `--encode` | Encrypt with `--shift` instead of breaking. |
| `--all` | Print all 26 shifts, ranked by score. |
| `--top K` | Show the top *K* candidates when auto-solving (default 3). |
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Force `raw`/`hex`/`base64` input decoding. |

## When to reach for it

- The ciphertext is alphabetic, roughly the length of the plaintext, and
  preserves word boundaries.
- The **Index of Coincidence** (`aesop freq`) is near **0.066** (English-like),
  indicating a *monoalphabetic* cipher rather than a polyalphabetic one.
- You see `ROT13`, `ROT47`, or "shift" hinted in a challenge.

If the IC is English-like but a Caesar solve fails, the cipher is probably a
**general substitution** — reach for `aesop substitution`. If the IC is low
(~0.04), suspect **Vigenère** (`aesop vigenere`) or a polyalphabetic scheme.

## See also

- `aesop manual substitution` — when a single shift isn't enough.
- `aesop manual vigenere` — many Caesars with a repeating key.
- `aesop manual scoring` — how "looks like English" is measured.
- `aesop manual misc` — Atbash, ROT47 and other fixed alphabets.

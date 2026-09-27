# The Vigenère Cipher

> Many Caesars in a trench coat. A repeating keyword hides the letter-frequency spikes that give a simple shift away — for three centuries it was *le chiffre indéchiffrable*.

## The fable

The fox in *The Fox and the Grapes* cannot reach the fruit, so he declares it
sour and walks away. For three hundred years cryptanalysts did much the same
with Vigenère: unable to reach the plaintext, they pronounced the cipher
unbreakable and moved on. Then Babbage and Kasiski found the ladder — the key
*repeats*, and repetition always leaves a footprint.

## How it works

Vigenère is a **polyalphabetic** substitution: a keyword is repeated across the
message and each key letter selects a Caesar shift for the plaintext letter
beneath it.

```
plaintext   A T T A C K A T D A W N
key         L E M O N L E M O N L E    (LEMON, repeated)
ciphertext  L X F O P V E F R N H R
```

Formally, with the key letter contributing shift `k` (A=0 … Z=25):

```
c = (p + k) mod 26          # encrypt
p = (c − k) mod 26          # decrypt
```

Because the same plaintext letter is enciphered under *different* shifts at
different positions, the flat, tell-tale English frequency profile is smeared
out. A single Caesar has 25 keys; a Vigenère with a length-*m* key has 26^*m*.
That is why frequency analysis — lethal against monoalphabetic ciphers — fails
here, and why the cipher held its "indecipherable" reputation for so long.

## Breaking it

The break is a **two-stage attack**: find the key *length*, then the key
*letters*. Once the length `m` is known, the cipher collapses into `m`
independent Caesar ciphers — one per key position — each of which is trivial.

### Stage 1 — find the key length

Two classic, complementary tools, both built in:

1. **Friedman / Index of Coincidence.** Deal the ciphertext into `L` columns
   (every `L`-th letter). If `L` is the true key length, each column is a pure
   Caesar slice of English and its **Index of Coincidence** (see
   `aesop manual scoring`) sits near **0.0667**; a wrong `L` scrambles the
   columns toward the random value **0.0385**. AESOP averages the columns' IC
   for every candidate length.
2. **Kasiski examination.** Repeated substrings in the plaintext that happen to
   line up with the key produce repeated substrings in the *ciphertext*, spaced
   a multiple of the key length apart. AESOP tallies the divisors of every such
   spacing; the key length collects the most votes. On short ciphertext — where
   IC is statistically noisy — Kasiski is often the decisive signal.

### Stage 2 — recover each column's shift

For each of the `m` columns, try all 26 shifts and keep the one whose decrypted
column best matches English letter frequencies (**chi-squared**,
`aesop manual scoring`). Read the winning shifts back as letters and you have
the keyword.

On long ciphertext that alone is exact. On short ciphertext each column holds
too few letters for chi-squared to be certain, so AESOP takes that guess as a
**seed** and polishes the whole key with **quadgram hill-climbing** (the same
fitness that ranks Caesar shifts), with random restarts to escape local optima.

## Using AESOP

```console
# Auto-break: no key, no length — AESOP finds both and prints the plaintext
$ aesop vigenere 'elq ehtgw pezaz tbi ngacd shse elq znkc pct xezm gtqqg bgid'

# Encrypt with a known keyword
$ aesop vigenere --encode -k lemon 'the quick brown fox jumps over the lazy dog'

# Decrypt with a known keyword
$ aesop vigenere -k lemon 'elq ehtgw pezaz tbi ngacd'

# Force a key length (e.g. when the IC/Kasiski evidence is ambiguous)
$ aesop vigenere --key-length 5 'elq ehtgw pezaz tbi ngacd shse elq'

# Show more key-length candidates in the diagnostic table
$ aesop vigenere --top 8 ciphertext.txt

# Pipes and files work everywhere
$ echo 'elq ehtgw pezaz tbi' | aesop vig
$ aesop vigenere -f ciphertext.txt
```

The recovered plaintext is always written on its own with `out.raw`, so the
command pipes cleanly into the next tool:

```console
$ aesop vigenere -q "$CT" | aesop freq        # feed the plaintext onward
```

### Options

| flag | meaning |
|------|---------|
| `-k, --key KEY` | Known keyword: decrypt with it (add `--encode` to encrypt). Non-letters in the key are ignored. |
| `--encode` | Encrypt the input with `--key` instead of breaking it. |
| `--key-length N` | Force the key length; AESOP recovers the best keyword of that length. |
| `--top N` | How many candidate key lengths to show in the evidence table (default 5). |
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Force `raw`/`hex`/`base64` input decoding (default: autodetect). |

## When to reach for it

- The ciphertext is alphabetic and roughly plaintext-length, but a Caesar solve
  (`aesop caesar`) fails and the letters look "too even".
- The overall **Index of Coincidence** (`aesop freq`) is low — around **0.04**,
  not the **0.066** of English — signalling a *polyalphabetic* cipher rather
  than a monoalphabetic one.
- A challenge hints at a **keyword**, "running key", or "Vigenère table /
  *tabula recta*".

If the IC is back up near 0.066, the cipher is monoalphabetic — reach for
`aesop caesar` or `aesop substitution`. If the recovered "key" is a single
letter, it was only a Caesar shift all along. **Beaufort** and the
**Vigenère-autokey** variants are close relatives; a short, wrong-looking key
whose length divides the text may indicate one of those.

## See also

- `aesop manual caesar` — one shift; the atom Vigenère is built from.
- `aesop manual substitution` — a single scrambled alphabet (high IC).
- `aesop manual scoring` — Index of Coincidence, chi-squared and quadgrams.
- `aesop manual freq` — measure the IC to tell mono- from poly-alphabetic.

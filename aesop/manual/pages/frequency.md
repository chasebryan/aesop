# Frequency Analysis — the cryptanalyst's dashboard
> Letters betray themselves by how often they turn up. `freq` counts them, compares to English, and hints at the cipher — and its key length.

## The fable

The tortoise beats the hare not by speed but by steady, patient counting. So too
the cryptanalyst: al-Kindi broke the monoalphabetic cipher in ninth-century
Baghdad simply by tallying letters and noticing that the most common ones must be
the most common plaintext letters in disguise. `freq` is that patient tortoise on
one screen.

## How it works

English is not random. `E`, `T`, `A`, `O`, `I`, `N` dominate; `Q`, `Z`, `X`, `J`
barely appear. A cipher that maps each plaintext letter to a *fixed* other letter
(Caesar, Atbash, general substitution) merely relabels this profile — the *shape*
survives, so the peaks still stand out, just under new names. `freq` shows you
that shape and four numbers that decide your next move.

### 1. Letter frequency vs English

The observed percentage of each letter, sorted, next to the English baseline and
the delta. On monoalphabetic ciphertext the profile is spiky (one letter near
12–13%). On a polyalphabetic cipher it flattens toward uniform.

### 2. Index of Coincidence (IC)

The probability that two letters picked at random are equal. It is invariant
under any monoalphabetic substitution, which makes it the single best cipher
classifier:

```
IC ≈ 0.0667   English (monoalphabetic: Caesar, substitution, or plaintext)
IC ≈ 0.0385   uniform random (or a long-key polyalphabetic cipher)
```

An IC near 0.066 says "one alphabet — reach for `aesop caesar` or
`aesop substitution`." An IC near 0.04 says "many alphabets — this is Vigenère."
See `aesop manual scoring` for the full family of measures.

### 3. Chi-squared vs English

A goodness-of-fit distance from the English letter distribution (lower = closer).
It separates *plaintext / Caesar* (letters may be shifted but the histogram is
English-shaped once you account for the shift) from a *general substitution*
(English-like IC, but a chi-squared that stays high because the peaks landed on
the wrong letters).

### 4. Bigrams & trigrams

The most common two- and three-letter sequences. In English these are `TH`,
`HE`, `IN` and `THE`, `AND`, `ING`. In weak ciphers they leak through as the most
common ciphertext n-grams, giving you cribs.

## Breaking Vigenère: the Kasiski examination

The killer feature for polyalphabetic ciphers. A repeating key means that when
the *same* plaintext substring lines up with the *same* stretch of key, it
encrypts to the *same* ciphertext. So repeated substrings in the ciphertext tend
to be separated by a multiple of the key length.

`freq` finds every repeated 3-gram, measures the gaps between occurrences, and
tallies which candidate key lengths divide those gaps. The winner (and its
multiples) is almost always the true period:

```console
$ aesop freq <vigenere-ciphertext>
...
 Kasiski key-length hints (Vigenère period)
  key length   supporting spacings
  5            ▇▇▇▇▇▇▇▇▇▇▇▇ 12
  10           ▇▇▇▇▇▇▇▇▇▇▇ 11
  ...
```

A clear peak at 5 (with support at 10, 15, …) means "key length 5 — hand it to
`aesop vigenere --key-length 5`."

## Using AESOP

```console
# Full dashboard on a ciphertext
$ aesop freq 'Lxfopvefrnhr ...'

# Pipe it in
$ echo 'Wkh txlfn eurzq ira' | aesop freq

# From a file
$ aesop freq -f ciphertext.txt

# Also list the most common n-grams of a given length (crib hunting)
$ aesop freq --ngrams 4 <ciphertext>
```

The first line printed is the compact `A:8.17 B:1.49 …` profile (pipe-friendly);
the tables and hints follow.

### Options

| flag | meaning |
|------|---------|
| `--ngrams N` | Also list the top *N*-grams (default shows bigrams/trigrams). |
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Decode as `hex`/`base64`/… before analysing (default: raw). |

## When to reach for it

- Any alphabetic ciphertext where you don't yet know the cipher.
- Deciding between Caesar/substitution (IC ≈ 0.066) and Vigenère (IC ≈ 0.04).
- Finding a Vigenère key length before running `aesop vigenere`.
- Hunting cribs via repeated n-grams.

Frequency analysis wants text: the more letters, the sharper every number. Under
~50 letters the IC and Kasiski hints get noisy — collect more ciphertext if you
can.

## See also

- `aesop manual caesar` — when the IC says monoalphabetic and a single shift fits.
- `aesop manual substitution` — English-like IC but stubbornly high chi-squared.
- `aesop manual vigenere` — feed it the Kasiski key length and let it solve.
- `aesop manual scoring` — IC, chi-squared and quadgrams, the full toolbox.
- `aesop manual identify` — one step earlier: what *is* this blob?

# Language Scoring — the engine behind every solver
> How AESOP measures "does this look like English?" — the fitness function that turns guessing into solving.

## Why it matters

A cipher-breaker is only as good as its ability to recognise the answer. When
AESOP tries all 26 Caesar shifts, hill-climbs a substitution key, or locks each
column of a Vigenère key, it is really doing one thing over and over: **scoring
candidate plaintexts and keeping the best**. Get the score right and the true
plaintext floats to the top on its own.

AESOP uses four complementary measures, each suited to a different job.

## 1. Quadgram log-probability (the workhorse)

The gold standard for monoalphabetic breaking. Real English has a very
distinctive distribution of 4-letter sequences (`TION`, `THAT`, `OFTH` are
common; `QKZX` never happens). AESOP ships a model of quadgram frequencies and
scores a candidate as the sum of log-probabilities of its overlapping quadgrams:

```
score(text) = Σ  log10 P(quadgram_i)
```

Unseen quadgrams get a small floor probability, so nonsense text is penalised
heavily. **Higher (less negative) is more English-like.** Because it is a sum,
compare only candidates of the *same length* (that's always the case inside a
solver); for cross-length comparison use the per-quadgram average.

The model lives in `aesop/data/english_quadgrams.txt.gz`. If it is ever missing,
AESOP falls back to a bigram + letter-frequency score so nothing breaks.

## 2. Index of Coincidence (cipher classification)

The probability that two letters drawn at random from the text are equal:

```
IC = Σ nᵢ(nᵢ − 1) / [ N(N − 1) ]
```

- **English ≈ 0.0667.** Monoalphabetic ciphers (Caesar, substitution) *preserve*
  the IC, because they just relabel letters.
- **Uniform random ≈ 0.0385.** Polyalphabetic ciphers with a long key push the
  IC down toward this.

So the IC tells substitution-like ciphers apart from Vigenère-like ones, and —
applied column by column — reveals the **Vigenère key length** (the length whose
columns each look monoalphabetic, IC ≈ 0.066).

## 3. Chi-squared frequency fit (fast, short-text)

Compares a candidate's letter distribution to English:

```
χ² = Σ (observedᵢ − expectedᵢ)² / expectedᵢ
```

**Lower is more English-like.** It needs no full-plaintext model, so it is ideal
for locking a single Caesar shift or one Vigenère column — including on short
text where quadgrams are unreliable.

## 4. Shannon entropy (bytes, not letters)

Bits of information per byte:

```
H = − Σ p(b) log₂ p(b)
```

- **~8.0** → encrypted or compressed (near-random bytes).
- **~4.0–4.5** → English text as bytes.
- **low** → structured / repetitive data.

Entropy is the first triage on an unknown *binary* blob — see `aesop entropy`.

## Seeing it yourself

```console
$ aesop freq -f cipher.txt        # IC, χ², letter table, n-grams
$ aesop entropy -f blob.bin       # Shannon entropy, overall and windowed
```

## See also

- `aesop manual caesar` / `substitution` / `vigenere` — the solvers that use these.
- `aesop manual frequency` — the `freq` command in detail.
- `aesop manual entropy` — entropy-based triage.

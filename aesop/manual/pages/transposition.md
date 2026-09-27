# Transposition Ciphers — Rail Fence & Columnar
> The letters never lie; only their order does. Same alphabet, shuffled seats.

## The fable

In *The Fox and the Stork*, the fox serves soup on a flat plate — everything is
present, nothing can be eaten, because the *arrangement* defeats the guest. A
transposition cipher is that plate: every plaintext letter is right there in
front of you, but the order has been rearranged so the message can't be read.
Restore the seating plan and the meal is served.

## How it works

A transposition cipher **permutes the positions** of the characters without ever
changing which letters appear. Two consequences follow immediately, and both are
diagnostic:

- The **letter-frequency histogram is unchanged** — `E` is still the most common
  letter, `Z` still rare.
- The **Index of Coincidence stays English-like (~0.066)**, exactly as for a
  substitution cipher. What gives a transposition away is that the letters look
  English but no *substitution* (Caesar, affine, Vigenère) turns the text into
  words: the damage is to order, not identity.

AESOP implements the two classic schemes.

### Rail fence

Write the plaintext in a zig-zag down and up across `R` rails, then read the
rails off top to bottom. With `R = 3` and `WEAREDISCOVEREDFLEEATONCE`:

```
W . . . E . . . C . . . R . . . L . . . T . . . E
. E . R . D . S . O . E . E . F . E . A . O . C . E   (illustrative zig-zag)
. . A . . . I . . . V . . . D . . . N . . . ...
```

Reading the rails in order yields `WECRLTEERDSOEEFEAOCAIVDEN`. The only key is
the **rail count**, so there are just a handful of possibilities — trivially
brute-forced.

### Columnar transposition

Write the plaintext into a grid **row by row** under a keyword, then read the
**columns** in the alphabetical order of the keyword's letters. Key `ZEBRA` ranks
its columns `A→1, B→2, E→3, R→4, Z→5`, i.e. read order `5 3 2 4 1`:

```
key:  Z E B R A          read order by rank: A,B,E,R,Z
      5 3 2 4 1
      -----------
      W E A R E
      D I S C O
      V E R E D
      F L E E A
      T O N C E
```

Reading columns A,B,E,R,Z → `EODAE ASREN EIELO RCEEC WDVFT` →
`EODAEASRENEIELORCEECWDVFT`. The key can be a **keyword** or an explicit
**digit permutation** (`31542`, or `3 1 5 4 2` for more than nine columns). When
the message doesn't fill the last row the trailing columns are shorter — AESOP's
decrypt handles this *irregular* case automatically.

## Breaking it

Both schemes yield to **brute force plus a language model**, because their key
spaces are small:

1. **Rail fence** — there are only `R−1` sensible rail counts. Try each, decrypt,
   and score the result with **quadgram log-probabilities** (see
   `aesop manual scoring`). The plaintext floats straight to the top.
2. **Columnar** — try each small column count `c` and *every* permutation of its
   `c` columns (`c!` of them), decrypt, and score. AESOP caps the search where
   `c!` gets expensive (default: through 7 columns, `perm_cap = 5040`) and prints
   a `hint` telling you exactly what was skipped, so you can widen it with
   `--max-cols`.

Because the search grows as `c!`, columnar breaking is reliable on real messages
but needs **enough ciphertext**: on very short blocks (a couple of dozen letters,
no word breaks) thousands of rival rearrangements can out-score the true reading
by chance. Give it a sentence or more and the true key wins cleanly.

## Using AESOP

```console
# Auto-solve: tries BOTH schemes, ranks by score, prints the best plaintext
$ aesop transposition 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDESCAPESINTOTHEFOREST'

# Restrict to one scheme and show more candidates
$ aesop transposition -t columnar --top 5 'EODAEASRENEIELORCEECWDVFT'

# Encode (rail fence, 3 rails)
$ aesop transposition --encode -t rail -r 3 'we are discovered flee at once'

# Encode (columnar, keyword)
$ aesop transposition --encode -t columnar -k ZEBRA 'wearediscoveredfleeatonce'

# Decode with a known key
$ aesop transposition -t rail -r 3      'WECRLTEERDSOEEFEAOCAIVDEN'
$ aesop transposition -t columnar -k ZEBRA 'EODAEASRENEIELORCEECWDVFT'

# Digit-permutation key, pipes and files
$ aesop transposition -t columnar -k 31542 -f cipher.txt
$ echo 'WECRLTEERDSOEEFEAOCAIVDEN' | aesop transpose -t rail -r 3
```

The recovered plaintext is always emitted on its own line via `raw` output, so
`transposition` composes in a pipeline (feed its result to `aesop caesar`, etc.).

### Options

| flag | meaning |
|------|---------|
| `-t, --type {rail,columnar,auto}` | Scheme to use; `auto` tries both and returns the best. |
| `-r, --rails N` | Rail-fence rail count — apply directly, or encode with it. |
| `-k, --key K` | Columnar key: a keyword (`ZEBRA`) or digit permutation (`31542`). |
| `--encode` | Encrypt with `--rails`/`--key` instead of breaking. |
| `--top K` | How many ranked candidates to show when auto-solving (default 3). |
| `--max-cols N` | Largest column count to try when breaking columnar (default 8). |
| `--max-rails N` | Largest rail count to try when breaking rail-fence (default 15). |
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Force `raw`/`hex`/`base64` input decoding. |

## When to reach for it

- The ciphertext is **alphabetic** and its **letter frequencies look English**
  (`aesop freq`), yet a Caesar / substitution solve produces nonsense.
- The **Index of Coincidence is ~0.066** (monoalphabetic-looking) but the message
  reads as an anagram of plausible English fragments.
- A challenge mentions "rails", "zig-zag", "columns", a keyword, or shows the
  ciphertext length as a tidy multiple of a small number.

If the IC is low (~0.04), suspect a *polyalphabetic* cipher instead
(`aesop vigenere`). If letter frequencies are flat/random, it isn't a
transposition at all — look at `aesop xor` or the modern attacks.

## See also

- `aesop manual caesar` — the simplest substitution, and a common outer layer.
- `aesop manual substitution` — when identities, not positions, are scrambled.
- `aesop manual vigenere` — polyalphabetic substitution (low IC).
- `aesop manual scoring` — how "looks like English" is measured (quadgrams).

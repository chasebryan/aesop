# Monoalphabetic Substitution Ciphers
> One alphabet, one disguise per letter — a keyspace of 26! that still falls to a fox that counts.

## The fable

In *The Fox and the Mask* the fox turns over a beautiful actor's mask and sighs:
"What a fine head — and no brains in it." A substitution cipher is that mask.
Its face is a huge and handsome keyspace — 26 factorial arrangements — but there
is nothing behind it: every letter keeps the *habits* of the language it came
from, and habits give it away.

## How it works

A monoalphabetic substitution cipher fixes an arbitrary permutation of the
alphabet as its key. Encryption replaces each plaintext letter with its partner
under the key:

```
key:        Q W E R T Y U I O P A S D F G H J K L Z X C V B N M
plaintext:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
```

So `A→Q`, `B→W`, `C→E`, … . Decryption applies the inverse permutation. Case is
preserved and non-letters pass through untouched.

Caesar and Atbash are *special cases* of this cipher (a rotation and a
reversal), but a general key is any of the

```
26! = 403,291,461,126,605,635,584,000,000 ≈ 4 × 10²⁶
```

possible permutations. That is far too many to enumerate — and yet the cipher is
weak, because it is *monoalphabetic*: a given plaintext letter always encrypts
to the same ciphertext letter. All the frequency structure of English survives
the encryption intact, merely relabelled.

## Breaking it

You cannot brute-force 26!, so you attack the statistics instead.

1. **Frequency analysis (the seed).** In English, `E T A O I N S H R D L …` are
   the common letters and `J Q X Z` the rare ones. Match the ciphertext's letter
   ranking to that profile and you get a rough first guess — usually a handful of
   letters already correct.
2. **Hill-climbing on quadgrams (the finish).** From that seed, repeatedly swap
   two letters of the key and keep the swap only if it makes the decrypted text
   *more English-like*, measured by summed **quadgram log-probabilities** (see
   `aesop manual scoring`). This is exactly how a human solves a newspaper
   cryptogram — spot `THE`, fix a letter, re-read, repeat — but run thousands of
   times a second.
3. **Random restarts.** Hill-climbing can get stuck in a local optimum (a
   near-miss key). Restarting from fresh random keys and keeping the best result
   escapes those traps. A few hundred letters of ciphertext are plenty for a
   near-perfect recovery.

AESOP does all three automatically. Randomness is seeded deterministically, so a
given ciphertext gives the same answer every run.

## Using AESOP

```console
# Auto-solve a cryptogram from a file: recover the key and print the plaintext
$ aesop substitution -f cryptogram.txt

# Or inline — 200+ letters solve reliably (this decrypts a fable about a fox)
$ aesop substitution 'P evfmkw udz rpt kaxi mkpxir epfmafm eame ukdo p safi \
  pfg nipxig pmpaf pfg pmpaf cd kipqe ceio, hvc cei rtiic ukvac rcpwig pntpwr \
  yvrc hiwdfg ear mkprx.'

# Try harder on a stubborn or short cryptogram
$ aesop substitution --restarts 40 --iterations 6000 -f cryptogram.txt

# Encrypt with a known key (a QWERTY-keyboard permutation)
$ aesop substitution --encode -k QWERTYUIOPASDFGHJKLZXCVBNM 'Attack at dawn'
Qzzqea qz rqvf

# Decrypt with a known key
$ aesop substitution -k QWERTYUIOPASDFGHJKLZXCVBNM 'Qzzqea qz rqvf'
Attack at dawn

# Pipes work too — the plaintext goes to stdout, diagnostics to the side
$ cat cryptogram.txt | aesop substitution | tee plaintext.txt
```

The recovered (or supplied) key is printed as an aligned
`plaintext → ciphertext` mapping, and the plaintext itself is written with
`out.raw`, so `| aesop substitution` stays pipe-friendly.

### Options

| flag | meaning |
|------|---------|
| `-k, --key KEY` | A 26-letter permutation of A–Z. Decodes with it (or encodes with `--encode`). |
| `--encode` | Encrypt the input with `--key` instead of breaking it. |
| `--restarts N` | Hill-climb restarts when auto-solving (default 30). More = more robust, slower. |
| `--iterations N` | Max key-swap evaluations per restart; sweeps stop early once converged (default 4000). |
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Force `raw`/`hex`/`base64` input decoding. |

## When to reach for it

- The ciphertext is alphabetic and roughly as long as the plaintext.
- The **Index of Coincidence** (`aesop freq`) is near **0.066**, i.e.
  English-like — the hallmark of a *monoalphabetic* cipher.
- A single Caesar shift (`aesop caesar`) fails to produce readable text even
  though the IC looks monoalphabetic — the letters have been scrambled by an
  arbitrary key, not a mere rotation.
- The break improves sharply with more ciphertext: aim for **200+ letters**.
  Below ~100 letters, rare letters (J, Q, X, Z) may stay unresolved.

If the IC is low (~0.04), the cipher is polyalphabetic — reach for
`aesop vigenere` instead. If word boundaries are preserved and the puzzle is
short, classic pattern-word analysis (a human cryptogram) can beat the solver on
the last few rare letters.

## See also

- `aesop manual caesar` — the 26-key special case (a pure rotation).
- `aesop manual vigenere` — a *poly*alphabetic cipher (many substitutions).
- `aesop manual scoring` — how "looks like English" (quadgrams, IC, χ²) is measured.
- `aesop manual freq` — frequency and IC triage to classify a cipher first.

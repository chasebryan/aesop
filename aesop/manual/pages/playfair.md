# The Playfair Cipher
> Encrypts letters two at a time on a 5x5 key square, flattening single-letter frequency — the first digraph cipher used seriously in the field.

## The fable

The fox never wrestles the whole hen-house at once; he waits by the one loose
board he already knows. Playfair looks formidable — a 25-cell square, letters
swapped in pairs, single-letter frequency erased — yet its keys are almost always
plain English words. AESOP tries the loose board first: every dictionary word as
a key. Only if that gate stays shut does it settle in for the long climb.

## How it works

Playfair (invented by Charles Wheatstone in 1854, championed by Lord Playfair)
encrypts **digraphs** — pairs of letters — against a **5x5 key square**.

**1. Build the square.** Write a key phrase into a 5x5 grid, dropping repeated
letters, then fill the rest of the alphabet in order. Because 26 letters don't
fit 25 cells, **I and J share a cell** (J is treated as I). Key `PLAYFAIR EXAMPLE`:

```
P L A Y F
I R E X M
B C D G H
K N O Q S
T U V W Z
```

**2. Prepare the plaintext.** Upper-case it, drop non-letters, fold J→I, then cut
it into pairs. Two rules keep every pair usable:

- A **doubled pair** (`LL`, `EE`) gets a filler inserted between the letters —
  conventionally `X` (`TREE` → `TR EX E…`).
- A **lone final letter** is padded, again with `X`.

**3. Encrypt each pair** by its geometry on the square:

| The pair is… | Encrypt rule | Decrypt rule |
|---|---|---|
| in the **same row** | take the letter to the **right** (wrap around) | letter to the **left** |
| in the **same column** | take the letter **below** (wrap around) | letter **above** |
| a **rectangle** (different row & column) | swap to the **other corner in the same row** | *the same swap* (self-inverse) |

`HI` → same? H is row 2 col 4, I is row 1 col 0 → rectangle → `BM`. Working the
whole message gives `HIDETHEGOLDINTHETREXESTUMP` → `BMODZBXDNABEKUDMUIXMMOUVIF`.

Decryption reverses the row/column shifts (the rectangle rule is its own
inverse). Note it recovers the **prepared** text — the inserted filler `X`s are
still there, because the cipher has no way to know which were padding.

## Why it was strong

A simple substitution cipher preserves single-letter frequency, so `E` stands
out and the whole thing unravels. Playfair encrypts **pairs**, so a plaintext
`E` becomes different ciphertext letters depending on its partner. There are
**600 possible digraphs**, their frequencies are far flatter than the 26 letters',
and the key space is a daunting 25! ≈ 1.5×10²⁵ squares. For a field cipher done
by hand, that was plenty.

## Breaking it

Two complementary attacks, both built in:

1. **Keyword dictionary attack (fast, reliable).** Real Playfair keys are
   English phrases. AESOP tries every word in the system dictionary as a key,
   decrypts, and scores each result with the English quadgram model
   (`aesop manual scoring`). For a word-based key this recovers the message in
   seconds — it is the first thing AESOP reaches for.
2. **Simulated annealing (general).** For a non-dictionary key, AESOP hill-climbs
   the 25-letter square directly: start from a random square, repeatedly **swap
   two letters** (occasionally two rows or two columns), keep changes that raise
   the quadgram score, and accept the occasional worse move with a probability
   that cools over time so the search escapes local optima. A greedy single-swap
   polish finishes each run, and several deterministically-seeded restarts widen
   the net.

Annealing is the honest general method, but Playfair's huge key space and the
narrowness of the true-key "basin" mean it needs **a lot of ciphertext** (roughly
150+ letters, more is better) and a strong language model. When the key is a real
word, the dictionary attack wins decisively — which is why AESOP tries it first
and only anneals if the result still doesn't read as English.

## Using AESOP

```console
# Encrypt with a known key (I/J merged, X-filled). --show-square draws the grid.
$ aesop playfair --encode -k 'PLAYFAIR EXAMPLE' 'Hide the gold in the tree stump'
BMODZBXDNABEKUDMUIXMMOUVIF

# Decrypt with a known key (fillers remain in the output)
$ aesop playfair --decode -k 'PLAYFAIR EXAMPLE' BMODZBXDNABEKUDMUIXMMOUVIF
HIDETHEGOLDINTHETREXESTUMP

# Auto-solve, no key: keyword attack first, annealing as a fallback
$ aesop playfair 'PDIMDZHPLIDMKLZNKSGAFYBXIOLBGARSKCPATCKFATRABTHYMPRMPI…'

# Show the recovered key square, and rank several candidates
$ aesop playfair --show-square --top 5 ciphertext.txt

# Force the general search (skip the dictionary), or point at your own wordlist
$ aesop playfair --sa-only --restarts 30 --iters 20000 ciphertext.txt
$ aesop playfair --wordlist my_keys.txt "$CIPHERTEXT"

# Pipe-friendly: the plaintext (or ciphertext) is emitted on its own line
$ echo "$CIPHERTEXT" | aesop playfair | tail -1
```

### Options

| flag | meaning |
|------|---------|
| `-k, --key PHRASE` | Key phrase for the 5x5 square. Required with `--encode`/`--decode`. |
| `--encode` | Encrypt the input with `--key`. |
| `--decode` | Decrypt the input with `--key` (filler letters are kept). |
| `--wordlist PATH` | Word list for the keyword attack (default: system dictionary). |
| `--sa-only` | Skip the keyword attack; use simulated annealing only. |
| `--restarts N` | Annealing restarts when auto-solving (default 14). |
| `--iters N` | Annealing iterations per restart (default 6000). |
| `--seed N` | Base RNG seed — the search is fully reproducible (default 0). |
| `--top K` | Show the top *K* candidate keys, ranked. |
| `--show-square` | Also print the 5x5 key square used or recovered. |
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Force `raw`/`hex`/`base64` input decoding. |

## When to reach for it

- The ciphertext is **all letters**, its length is **even**, and it contains
  **no doubled letters** in any pair (Playfair can never output `XX`, `EE`, …).
- The **Index of Coincidence** (`aesop freq`) sits **between** monoalphabetic
  English (~0.067) and random (~0.038) — often ~0.045–0.06 — and a Caesar and a
  simple-substitution solve both fail.
- `J` is conspicuously absent, or the challenge names Playfair, Wheatstone, or a
  "5x5 square".

If a substitution solve works, it was never Playfair. If the IC is very low
(~0.04) and the alphabet is full, suspect **Vigenère** or another polyalphabetic
scheme instead.

## See also

- `aesop manual substitution` — the monoalphabetic cousin Playfair improves on.
- `aesop manual vigenere` — the other classic step up from Caesar.
- `aesop manual scoring` — how "looks like English" (quadgrams) is measured.
- `aesop manual freq` — Index of Coincidence and frequency triage.

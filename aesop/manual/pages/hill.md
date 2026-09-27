# The Hill Cipher
> Letters travel in packs. A secret matrix scrambles whole blocks at once — beating frequency analysis, yet undone by the very algebra that powers it.

## The fable

In *The Lion and the Mouse*, the mighty lion is freed not by force but by a small
creature gnawing one rope. The Hill cipher is that lion: it looks impregnable —
whole blocks of letters vanish into a matrix, and counting single letters tells
you nothing. But it is built from straight lines. Hand the fox a few gnawed
threads — a scrap of plaintext beside its ciphertext — and the whole knot falls
apart. No guessing, no scoring: one modular matrix inverse and the key is his.

## How it works

Number the letters A=0, B=1, …, Z=25. Choose a block size `n` and a secret
`n × n` **key matrix** `K` of numbers mod 26. Split the plaintext into blocks of
`n` letters, treat each block as a vector `p`, and multiply:

```
c = p · K   (mod 26)
```

Decryption multiplies by the modular inverse of the key:

```
p = c · K⁻¹  (mod 26)
```

`K⁻¹` is computed the classical way — `K⁻¹ ≡ det(K)⁻¹ · adj(K) (mod 26)` — where
`adj(K)` is the adjugate (transposed cofactor matrix) and `det(K)⁻¹` is the
modular inverse of the determinant (AESOP uses `aesop.core.util.modinv`). A short
final block is padded with `X`.

### Why the key must be invertible mod 26

The map can only be undone if `K` has an inverse over `Z_26`, and that happens
exactly when **`det(K)` is coprime with 26** — i.e. the determinant is **odd**
and **not a multiple of 13**. If the determinant shares a factor with 26 (= 2 ·
13), several plaintext blocks collide on the same ciphertext and decryption is
impossible. AESOP checks this and tells you plainly when a key is unusable.

### A worked 2×2 example

Key `K = [[3,3],[2,5]]` (flat: `3,3,2,5`), plaintext `HELP`:

```
H,E = 7,4    →  [7,4]·K = [7·3+4·2, 7·3+4·5] = [29,41] = [3,15]  → D,P
L,P = 11,15  →  [11,15]·K = [63,108]         = [11,4]  → L,E
```

So `HELP` enciphers to `DPLE`. The determinant is `3·5 − 3·2 = 9`, which is
coprime with 26, so the key is valid and `DPLE` decrypts cleanly back to `HELP`.

## Breaking it

Frequency analysis fails — that is the whole point of a polygraphic cipher — so
the practical attack is the **known-plaintext attack**, which is devastating
because the cipher is *linear*:

1. Collect `n` plaintext blocks whose ciphertext you know.
2. Stack the plaintext blocks as the rows of a matrix `P` and the matching
   ciphertext blocks as the rows of `C`. Then `P · K = C (mod 26)`.
3. Recover the key by inverting the **plaintext** block matrix:

```
K = P⁻¹ · C   (mod 26)
```

That is one modular matrix inverse — no search, no language model. The only
requirement is that the `n` chosen plaintext blocks be **independent mod 26** so
`P` inverts; if the first `n` are dependent, AESOP automatically tries other
combinations of the blocks you supplied.

Without any known plaintext you are reduced to guessing the block size and
brute-forcing invertible matrices (only feasible for `n = 2`, where a crib and
scoring can help), which is why a single matched crib is the fox's favourite way
in.

## Using AESOP

```console
# Encode with a known key (row-major flat CSV; block size inferred as √4 = 2)
$ aesop hill --encode --key '3,3,2,5' 'HELP'
DPLE

# Decode with that key
$ aesop hill --decode --key '3,3,2,5' 'DPLE'
HELP

# Recover the key from a matched plaintext/ciphertext pair
$ aesop hill --known 'HELP' --cipher 'DPLE' --size 2
3,3,2,5

# A 3×3 key: nine numbers, --size inferred as √9 = 3
$ aesop hill --encode --key '6,24,1,13,16,10,20,17,15' 'ACT'

# Works with pipes and files too
$ echo 'DPLE' | aesop hill --key '3,3,2,5'
$ aesop hill --decode -f cipher.txt --key '3,3,2,5'
```

The recovered key prints as a flat CSV on its own line (pipe it straight into a
`--decode` run) followed by a readable matrix.

### Options

| flag | meaning |
|------|---------|
| `-k, --key CSV` | Key matrix as flat, row-major CSV (e.g. `3,3,2,5`). |
| `-s, --size N` | Block size *n* (matrix is *n×n*); inferred from key length otherwise. |
| `--encode` | Encrypt the input with `--key`. |
| `--decode` | Decrypt the input with `--key` (the default when a key is given). |
| `--known PLAIN` | Known plaintext for a key-recovery attack (with `--cipher`). |
| `--cipher CIPHER` | Ciphertext matching `--known` (same length). |
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Force `raw`/`hex`/`base64` input decoding. |

Give `--key` without `--encode` and AESOP **decodes**; add `--encode` to go the
other way. For the attack, `--known` and `--cipher` must be the same length and
provide at least `n` blocks (`n²` letters).

## When to reach for it

- The ciphertext is alphabetic and its length is a **multiple of 2, 3, …** (a
  clean block size), yet no monoalphabetic or Vigenère solve works.
- The **Index of Coincidence** (`aesop freq`) is **low** (~0.04–0.05), like a
  polyalphabetic cipher — single-letter frequencies look flattened because
  letters were mixed in blocks.
- You have, or can guess, a **crib**: a stretch of known or probable plaintext
  aligned to its ciphertext. That is all a known-plaintext attack needs.

If the IC is English-like (~0.066) and word boundaries survive, you are almost
certainly looking at a monoalphabetic cipher instead — reach for `aesop caesar`,
`aesop affine` or `aesop substitution`.

## See also

- `aesop manual affine` — the 1×1 "Hill" cipher: multiply-then-shift a single letter.
- `aesop manual substitution` — the other way to beat single-letter frequency counts.
- `aesop manual vigenere` — the other classic with a low, flattened IC.
- `aesop manual scoring` — Index of Coincidence and the fitness functions behind classification.

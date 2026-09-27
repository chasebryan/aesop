# XOR — Single-byte & Repeating-key
> The exclusive-or is the fox of ciphers: quick, symmetric, and disarmingly simple — right up until a short or reused key gives the whole game away.

## The fable

The fox in *The Fox and the Grapes* convinces himself the unreachable fruit is
sour. A reused XOR key is the opposite trap: the prize looks unreachable, yet the
key's own repetition is the ladder that hands it to you. What protects a one-time
pad — a key as long as the message, never reused — is exactly what a repeating
key throws away.

## How it works

XOR combines each plaintext byte with a key byte:

```
c = p ⊕ k
```

Because `x ⊕ k ⊕ k == x`, the *same* operation encrypts and decrypts — there is
no separate "decrypt" direction. Two schemes matter in practice:

- **Single-byte XOR.** One byte `k` (0–255) is XORed with every plaintext byte.
  The keyspace is 256 — trivially exhaustible.
- **Repeating-key XOR** (byte-wise Vigenère). A short key `k0 k1 … k_{m-1}` is
  cycled over the message: `c_i = p_i ⊕ k_{i mod m}`. Every `m`-th byte shares one
  key byte, so the cipher is really *m* interleaved single-byte XORs.

Used correctly — a random key as long as the message, used once — XOR is the
information-theoretically perfect **one-time pad**. Every weakness below comes
from breaking one of those rules.

## Breaking it

### Single-byte

Try all 256 keys and score each candidate for English-likeness. AESOP blends
three cues (see `aesop manual scoring`):

1. **Printable ratio** — the wrong key sprays control bytes.
2. **Letter/space frequency** — the dominant signal, since a column is a
   *subsequence* of English, not running prose.
3. **Quadgram log-probability** — refines the ranking once text looks plausible.

### Repeating-key (the cryptopals attack)

1. **Find the key length.** For each candidate length `m`, cut the ciphertext
   into `m`-byte blocks and measure the average **Hamming distance** (differing
   bits) between successive blocks, divided by `m`. Blocks encrypted under the
   *same* key bytes differ only as much as their plaintexts do (~2.6–3.3 bits per
   byte for English), well below the ~4.0 of unrelated data — so the true length
   and its multiples sink to the bottom of the ranking.
2. **Transpose.** Regroup the ciphertext into `m` columns, where column `j` holds
   every byte encrypted with key byte `k_j`.
3. **Solve each column** as an independent single-byte XOR.
4. **Reassemble** the recovered bytes into the key. AESOP then collapses a
   periodic result (`KEYKEY` → `KEY`) so the minimal key is reported.

## Using AESOP

```console
# Break single-byte XOR (hex auto-detected)
$ aesop xor 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

# Auto-detect single vs repeating and solve; input can be hex/base64/raw
$ aesop xor -f cipher.b64
$ cat secret.hex | aesop xor --top 5

# Force a mode, or a known key length
$ aesop xor --repeating cipher.b64
$ aesop xor --keysize 3 cipher.hex

# Apply a key (encrypt OR decrypt — XOR is symmetric)
$ aesop xor -k ICE 'Burning \'em, if you ain\'t quick and nimble'
$ aesop xor --key-type hex -k 4b4559 -e hex 5f101d0c1a4b0e   # decrypt hex with a hex key
```

The recovered (or transformed) bytes are printed with `out.raw` — as text when
printable, otherwise as hex — so the command pipes cleanly into the next tool.
The discovered key (ASCII + hex) and diagnostic tables are shown alongside.

### Options

| flag | meaning |
|------|---------|
| `-k, --key` | Apply this key instead of solving. |
| `--key-type {ascii,hex}` | How to read `--key` (default `ascii`). |
| `--single` | Force single-byte mode when solving. |
| `--repeating` | Force repeating-key mode when solving. |
| `--keysize N` | Break repeating XOR with a known key length (skip detection). |
| `--top K` | Show the top *K* single-byte candidates (default 3). |
| `-f, --file` | Read input from a file. |
| `-e, --in-encoding` | Force `raw`/`hex`/`base64` input decoding. |

## When to reach for it

- The ciphertext is arbitrary bytes (high **entropy** — `aesop entropy`), often
  delivered as **hex** or **base64**, not as alphabetic text.
- You suspect a stream cipher / keystream reuse: XORing two messages encrypted
  under the same keystream cancels the key (`c1 ⊕ c2 == p1 ⊕ p2`).
- A CTF hands you a `.hex`/`.b64` blob and hints at "xor", "key", or a short
  passphrase.

If a repeating-key solve looks *almost* right but the key length seems doubled,
it was likely a multiple of the true length — AESOP already reduces it, but you
can confirm with `--keysize`. If the plaintext itself is another cipher, pass it
back through `aesop detect` or `aesop magic`.

## See also

- `aesop manual vigenere` — the alphabetic cousin (mod-26 instead of mod-256).
- `aesop manual scoring` — how "looks like English" is measured.
- `aesop manual entropy` — telling XOR ciphertext from encoded text.
- `aesop manual magic` — peel encoding layers before/after an XOR break.

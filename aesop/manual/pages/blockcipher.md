# Block-Cipher Modes: ECB Detection & CBC Padding Oracles
> The cipher was strong; the *mode* was not. Two classic ways a block cipher leaks — and how AESOP catches them.

## The fable

In *The Fox and the Grapes* the fruit is perfectly good; it is the fox's approach
that fails. A block cipher like AES is those grapes — sound in itself. But wrap
it in the wrong **mode of operation** and the whole system spoils. This page is
about two spoiled modes every cryptanalyst learns to smell: **ECB**, which
repeats itself, and **CBC with a padding oracle**, which cannot keep a secret
once you ask it the right yes/no question enough times.

## Background: modes of operation

A block cipher only encrypts one fixed-size block (AES: 16 bytes). To encrypt a
longer message you chain blocks together with a *mode*:

- **ECB (Electronic Codebook)** encrypts every block independently:
  `C_i = E_k(P_i)`. Identical plaintext blocks therefore produce **identical**
  ciphertext blocks — a structural leak.
- **CBC (Cipher Block Chaining)** XORs each plaintext block with the previous
  ciphertext block before encrypting: `C_i = E_k(P_i XOR C_{i-1})`, with `C_0`
  seeded by an IV. Decryption is `P_i = D_k(C_i) XOR C_{i-1}`.

CBC hides the repetition ECB exposes — but its decryption structure enables the
padding-oracle attack below.

## Weakness 1 — ECB detection

Because ECB maps equal plaintext blocks to equal ciphertext blocks, any
repetition in the plaintext (a run of spaces, a repeated record, a large image
with flat colour — the infamous *ECB penguin*) shows straight through into the
ciphertext. Random or CBC ciphertext essentially never repeats a full 16-byte
block, so **even one repeated aligned block is a strong ECB signal.**

### How AESOP detects it

1. Slice the ciphertext into aligned `block`-byte chunks.
2. Count how many chunks duplicate an earlier one.
3. Report the count, and rank candidate block sizes (8/16/32) by how much they
   repeat — the true block size maximises the repeat rate.

```console
# 0011..55 repeated three times = an unmistakable ECB fingerprint
$ aesop blockcipher --ecb-detect 00112233445566778899001122334455\
00112233445566778899001122334455

# From a file or a pipe (hex/base64 auto-detected)
$ cat cipher.hex | aesop block --ecb-detect
$ aesop blockcipher --ecb-detect -f captured.b64
```

The primary output line is greppable —
`ecb=yes block=16 repeated_blocks=2 total_blocks=4` — and a table breaks down the
repeat rate per candidate block size plus the offending duplicate blocks.

## Weakness 2 — the CBC padding oracle

This is the crown jewel. Suppose a server decrypts your CBC ciphertext and does
nothing more than tell you (directly, or via a timing/error difference) **whether
the PKCS#7 padding was valid.** That single leaked bit lets you decrypt *any*
ciphertext, byte by byte, without ever learning the key.

### PKCS#7 padding

To fill the last block, PKCS#7 appends *N* bytes each equal to *N* (so `03 03 03`
pads three bytes; a whole extra block of `10 10 … 10` is added when the data is
already aligned). Unpadding checks that the final byte *N* is in range and that
the last *N* bytes all equal *N*.

### The attack

Recall `P_i = D_k(C_i) XOR C_{i-1}`. The attacker controls `C_{i-1}` (just send a
forged block), so they control the XOR that lands on the decrypted block. To
recover the last byte of block *i*:

1. Forge the previous block byte `C'[15]` and submit `C' || C_i`.
2. Try all 256 values. When the oracle says "valid", the decrypted last byte is
   almost certainly `0x01`, so `D_k(C_i)[15] = C'[15] XOR 0x01`.
3. XOR that intermediate byte with the **real** previous block to get the true
   plaintext byte.
4. Fix that byte to make padding `0x02`, march left to byte 14, and repeat —
   right to left across the block, then block to block.

A perturb-and-recheck step removes the one false positive that can occur on the
final byte (when the message already ended in longer valid padding). AESOP's
`padding_oracle_decrypt` handles all of this.

### Using AESOP

The oracle is **your own local program** — the standard CTF setup, where the
challenge ships a checker. Pass it with `--oracle`, using `{}` where the hex
ciphertext should be substituted:

```console
# oracle.sh exits 0 (or prints "valid") iff padding is good
$ aesop blockcipher --oracle './oracle.sh {}' 9f0b3c...c1

# Recover the first block too by supplying the IV
$ aesop blockcipher --oracle 'python3 check.py {}' \
      --iv 00000000000000000000000000000000 c1d2e3...
```

Validity is read from the command: stdout containing `invalid` → invalid; else
stdout containing `valid` → valid; otherwise exit code `0` means valid. The
recovered plaintext is emitted with `out.raw` (PKCS#7 stripped when it checks
out), so you can pipe it onward.

> Note: `--oracle` runs a local shell command you provide, once per probe (up to
> 256 × block-size × number-of-blocks times). Only point it at a checker you
> trust, and expect it to be slow if each probe spawns a process.

## Bonus — CBC bit-flipping

The same "attacker controls the XOR" insight lets you *tamper* rather than
decrypt. If you know a slice of plaintext in block *i* and want it to say
something else, XOR the previous ciphertext block with `known XOR desired`
(scrambling block *i−1* as the price). The programmatic API exposes this as
`cbc_bitflip(known, desired, offset=…, block=…)` — the go-to move for forging
`admin=true` in a CBC-protected cookie.

### Options

| flag | meaning |
|------|---------|
| `--ecb-detect` | Scan for repeated aligned blocks (the default action). |
| `--oracle 'CMD {}'` | External padding oracle; `{}` ← hex ciphertext. Mounts the CBC padding-oracle decrypt. |
| `--block N` | Cipher block size in bytes (default 16, i.e. AES). |
| `--iv HEX` | IV as hex; supply it to also recover the first block under `--oracle`. |
| `--oracle-timeout S` | Per-probe timeout for `--oracle`, in seconds (default 30). |
| `-f, --file` | Read the ciphertext from a file. |
| `-e, --in-encoding` | Force `raw`/`hex`/`base64` input decoding. |

## Programmatic API

```python
from aesop.modern.blockcipher import (
    detect_ecb, find_block_size, repeated_blocks,
    pkcs7_pad, pkcs7_unpad, pkcs7_valid,
    cbc_bitflip, padding_oracle_decrypt,
)

is_ecb, reps = detect_ecb(ciphertext, block=16)

# oracle is any callable(ciphertext_bytes) -> bool
plaintext = pkcs7_unpad(padding_oracle_decrypt(oracle, ciphertext, block=16, iv=iv))
```

## When to reach for it

- The ciphertext length is an exact multiple of 16 (or 8) bytes and you suspect a
  block cipher — start with `--ecb-detect`.
- You see repeated 16-byte runs in a hex dump, or high entropy with visible
  structure (`aesop entropy`, `aesop identify`).
- A service decrypts attacker-supplied ciphertext and reveals a padding /
  decryption error (or a timing difference) — that is a padding oracle; reach for
  `--oracle`.
- You control the previous block or IV and want to flip chosen plaintext bytes —
  use `cbc_bitflip`.

## See also

- `aesop manual xor` — the atom underneath CBC chaining and bit-flipping.
- `aesop manual entropy` — triage: is this blob even encrypted?
- `aesop manual rsa` — the other half of the modern-attacks shelf.
- `aesop manual auto` — let AESOP triage an unknown blob for you.

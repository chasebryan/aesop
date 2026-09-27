# RSA — Textbook Attack Suite
> RSA is only as strong as the way it's used. This is the fox's bag of tricks for every classic misuse: close primes, tiny keys, un-padded messages, reused moduli and shared primes.

## The fable

In *The Fox and the Grapes*, the fox cannot reach the fruit and decides it was
sour anyway. Textbook RSA is the opposite temptation: the grapes hang *low*.
Whenever a key is generated lazily or a message is sent without padding, a whole
vineyard drops within reach — and each shortcut has its own fox waiting beneath
the vine.

None of what follows breaks *properly* padded, properly generated RSA. It breaks
the mistakes — which is exactly the RSA you meet in CTFs and coursework.

## How RSA works

A public key is a modulus `n = p·q` (two secret primes) and an exponent `e`.
Encryption of a message integer `m` is:

```
c = m^e mod n
```

Decryption uses the private exponent `d`, the inverse of `e` modulo the totient
`φ(n) = (p−1)(q−1)`:

```
m = c^d mod n        where   e·d ≡ 1  (mod φ(n))
```

Security rests entirely on **factoring `n` being hard**. Recover `p` and `q` and
you can compute `φ`, then `d`, then every message. Everything in this suite is
either a way to factor `n` cheaply, or a way to skip factoring altogether by
exploiting how the ciphertext was produced.

## The attacks

Each is a pure function in `aesop.modern.rsa` and a `--attack` choice on the CLI.

### Factoring `n`

| attack | wins when | idea |
|--------|-----------|------|
| `factordb` | `n` is already known online | look it up in factordb.com |
| `fermat` | `p` and `q` are **close** | write `n = a² − b² = (a−b)(a+b)`, walk `a` up from `⌈√n⌉` |
| `pollard-pm1` | some `p−1` is **B-smooth** | `gcd(a^{B!} − 1, n)` reveals such a `p` |
| `pollard-rho` | a factor is **small** (≲ 70 bits) | Brent's cycle-finding walk, cost `~⁴√n` |
| `common-factor` | **many keys** share a prime | pairwise `gcd(n_i, n_j)` across a keyfile |

Fermat is devastating because "close" is common: naive keygen sometimes picks
`q = nextprime(p)`. If `|p − q|` is on the order of `√[4]{n}`, Fermat finishes in
a handful of steps.

Batch-GCD (`common-factor`) is the real-world classic: two devices that booted
with the same weak entropy pool can generate different moduli that nonetheless
*share one prime*. A single `gcd` then factors **both**.

### Skipping the factoring

| attack | scenario | idea |
|--------|----------|------|
| `wiener` | `d` is **small** (`d < ⅓·n^¼`) | `k/d` appears among the convergents of the continued fraction of `e/n` |
| `lowe` | small `e`, no padding, `m^e < n` | the ciphertext *is* a perfect power: take the integer `e`-th root |
| `hastad` | same `m` sent to **`e` recipients** under a small `e` | CRT the `c_i` together, then take the `e`-th root |
| `common-modulus` | same `m`, same `n`, two **coprime** `e`s | Bézout: `m = c1^a · c2^b mod n` where `a·e1 + b·e2 = 1` |

Wiener punishes anyone who shrinks `d` to make decryption fast. Låttice methods
(Boneh–Durfee) push the bound further, but Wiener alone clears the classic
`d < n^{0.25}` case instantly.

The low-exponent family (`lowe`, `hastad`) punishes missing padding with `e = 3`:
if the message never wraps the modulus, exponentiation is just cubing, and cubing
is trivially reversible over the integers.

### Reconstruction

Given any workable subset of parameters — `(p, q, e)`, `(n, φ, e)`, `(n, e, d)`
or a ready `(n, d)` — AESOP fills in the rest arithmetically (no search) and, if
you supply a ciphertext `c`, decrypts it. `φ` alone yields `p, q` by solving the
quadratic `x² − (n − φ + 1)x + n`; a leaked `d` yields them via the `e·d − 1`
square-root method.

## Using AESOP

Every integer accepts decimal or `0x` / `0o` / `0b`, with `_` separators allowed.
The recovered message prints twice via `out.raw` — as an integer, then decoded to
bytes — so it pipes cleanly into whatever comes next.

```console
# Auto: give what you have and let AESOP pick the attack order
$ aesop rsa -n 0x... -e 65537 -c 0x...

# Close primes
$ aesop rsa --attack fermat -n <N> -e <E> -c <C>

# Tiny private exponent
$ aesop rsa --attack wiener -n <N> -e <E> -c <C>

# Un-padded cube (e = 3), message smaller than the modulus
$ aesop rsa --attack lowe -e 3 -n <N> -c <C>

# Same message under two coprime exponents on one modulus
$ aesop rsa --attack common-modulus -n <N> -e 3 -c <C1> -e 5 -c <C2>

# Håstad broadcast: e ciphertexts under e different moduli
$ aesop rsa --attack hastad -e 3 -c <C1> -n <N1> -c <C2> -n <N2> -c <C3> -n <N3>

# Batch-GCD a pile of public keys from a file
$ aesop rsa --attack common-factor -f moduli.txt

# Rebuild a key from partial knowledge and decrypt
$ aesop rsa -p <P> -Q <Q> -e 65537 -c <C>
$ aesop rsa -n <N> --phi <PHI> -e 65537 -c <C>
```

A `--file` holds one `name = value` per line (`n`, `e`, `c`, `p`, `q`, `d`,
`phi`; `n`/`e`/`c` may repeat), with `#` comments and bare-integer lines treated
as extra ciphertexts:

```text
# harvested public keys
n = 0xC0FFEE...
n = 0xDEADBEEF...
e = 65537
c = 0x1234...
```

### Options

| flag | meaning |
|------|---------|
| `-n, --modulus N` | Modulus `n`. Repeatable for multi-key attacks. |
| `-e, --exponent E` | Public exponent `e`. Repeatable (e.g. common-modulus). |
| `-c, --ciphertext C` | Ciphertext integer `c`. Repeatable (hastad/broadcast). |
| `-p, --prime-p P` | Known prime factor `p`. |
| `-Q, --prime-q Q` | Known prime factor `q` (`-q` is reserved for `--quiet`). |
| `-d D` | Known private exponent `d`. |
| `--phi PHI` | Known totient `φ(n)`. |
| `--attack` | `auto` (default), `fermat`, `wiener`, `pollard-pm1`, `pollard-rho`, `lowe`, `hastad`, `common-modulus`, `common-factor`, `factordb`. |
| `-B, --bound B` | Smoothness bound for Pollard p−1. |
| `--max-iters` | Iteration cap for Fermat / rho. |
| `-f, --file` | Read parameters from a file (see above). |

`auto` tries the applicable attacks in a sensible order — direct reconstruction,
then batch-GCD, common-modulus, Håstad, low-exponent, and finally a factoring
ladder (small/smooth → Wiener → Fermat → p−1 → rho) — and stops the moment it
factors `n` or recovers `m`. Long-running methods are bounded; when `auto` gives
up it prints a `hint` naming what it skipped and what to try next.

## When to reach for it

- You have `n`, `e`, `c` and want the plaintext — start with plain `auto`.
- `n` factors as two suspiciously **close** primes → `fermat`.
- `e` is huge and near `n` (a sign `d` was made small) → `wiener`.
- `e` is `3` (or another tiny value) and the message looks short → `lowe`.
- You captured the **same secret** encrypted several ways → `common-modulus`
  (one modulus) or `hastad` (many moduli, same small `e`).
- You have a **directory of public keys** from weak devices → `common-factor`.

If none apply and `n` is genuinely large with balanced primes, textbook attacks
end here — that is real RSA doing its job. Lattice attacks (Coppersmith,
Boneh–Durfee) are the next frontier and need the optional `fpylll`.

## See also

- `aesop manual getting-started` — input encodings, piping, and the `-e` flag.
- `aesop identify` / `aesop manual magic` — triage an unknown blob before you
  assume it's RSA.
- `aesop manual xor` — the other CTF perennial once the number theory is done.

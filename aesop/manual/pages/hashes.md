# Hashes — Identify, Digest, Crack & Length-Extend
> Reading a hash by its footprint, then either matching it to a word or bending it to your will. Four commands, one page.

## The fable

The fox never needed to *see* the hare to know it had passed — the track in the
mud told the whole story: its size, its gait, which way it ran. A hash is a
track. It is not the thing itself, but its length, its alphabet and the little
`$`-marks at its head betray exactly what made it. This page teaches you to read
the track (`hash-id`), to leave one of your own (`hash`), to walk it backwards
when the ground is soft (`crack`), and — for the older, careless quarry — to
extend the trail past where its maker meant it to end (`length-extension`).

---

## What a cryptographic hash is

A hash function `H` maps arbitrary bytes to a fixed-size digest. A good one is:

- **deterministic** — same input, same digest, always;
- **one-way** — infeasible to recover the input from the digest;
- **collision-resistant** — infeasible to find two inputs with the same digest.

MD5 and SHA-1 fail the last two properties today and are broken for security,
but they are everywhere in legacy systems and CTFs — which is exactly why a
cryptanalyst still needs to handle them fluently.

---

## `hash-id` — name the algorithm

You cannot attack a digest until you know what produced it. AESOP guesses from
three signals:

1. **Structured prefix.** Modular-crypt and framework hashes announce themselves:
   `$2b$` bcrypt, `$6$` sha512-crypt, `$1$` md5-crypt, `$argon2id$`, `{SSHA}`
   LDAP, `$P$` phpass, `*` + 40 hex for MySQL 4.1+. These are near-certain.
2. **Length.** A bare hex string's character count pins the digest size: 32 →
   MD5/NTLM/MD4, 40 → SHA-1/RIPEMD-160, 56 → SHA-224, 64 → SHA-256, 96 →
   SHA-384, 128 → SHA-512, 8 → CRC-32.
3. **Ranking by prevalence.** At each length several algorithms are possible;
   AESOP orders them by how common they are in the wild (MD5 before NTLM before
   MD4 at 32 hex).

```console
$ aesop hash-id 5f4dcc3b5aa765d61d8327deb882cf99
md5
ntlm
md4
lm
ripemd128
md2
md5(md5(x))
        hash-id — 32 chars
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ algorithm   ┃ confidence ┃ notes                                ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ md5         │        75% │ MD5 — by far the most common 32-hex … │
└─────────────┴────────────┴──────────────────────────────────────┘
```

The ranked names print first (one per line) so `aesop hash-id X | head -1` gives
you the single best guess in a script.

---

## `hash` — compute a digest

A digest calculator with a wider menu than `md5sum` and friends: every algorithm
hashlib offers on this build, plus **md4**, **ntlm** (MD4 of the UTF-16LE
password — the Windows hash), **crc32** and **adler32**.

```console
# One algorithm → just the digest (pipe-friendly)
$ aesop hash -a sha256 'hello'
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

# No --algo → a common set (md5, sha1, sha256, sha512)
$ aesop hash 'password'

# Everything
$ aesop hash --all 'secret'

# Hash a file's raw bytes
$ aesop hash -a sha1 -f payload.bin
```

Input is always taken as **raw bytes** — never sniffed as hex or base64 — so a
password that happens to look like base64 is hashed as typed. Use `-f`/stdin for
binary input.

---

## `crack` — dictionary attack

For a **fast, unsalted** digest (md5, sha1, sha256, ntlm, …), the quickest way
back to the plaintext is to hash a dictionary and compare.

### How it works

For each word in the wordlist AESOP tries the word itself plus cheap, high-yield
mutations:

- case variants — lower, UPPER, Capitalised;
- a trailing digit `0`–`9`;
- a common suffix — `123`, `!`, `2025`, `password`, and similar.

Each candidate is hashed and compared to the target. The first match is the
preimage.

```console
$ aesop crack -a md5 5f4dcc3b5aa765d61d8327deb882cf99
  cracking md5 against /usr/share/dict/words (with case/suffix mutations)
✓ cracked in 148 tries
password

# Infer the algorithm from the digest length
$ aesop crack 5d41402abc4b2a76b9719d911017c592

# A bigger wordlist, verbatim only, with a safety cap
$ aesop crack -a sha1 -w rockyou.txt --no-mutations --max 5000000 <digest>
```

Progress and any cap are logged as hints on stderr-style lines; the recovered
password is emitted with `out.raw` so it pipes cleanly.

**Scope.** This is a *dictionary* attack on *unsalted* hashes. Salted and
deliberately-slow schemes (bcrypt `$2b$`, sha512-crypt `$6$`, argon2) are not
handled here — identify them with `hash-id` and reach for a purpose-built
cracker. There is no brute-force keyspace search: unknown passwords outside the
wordlist will not be found.

---

## `length-extension` — forge a MAC

A naive message-authentication scheme computes `MAC = H(secret ‖ message)` with a
Merkle–Damgård hash (MD5, SHA-1, SHA-256). This is **forgeable** without knowing
the secret.

### Why it works

A Merkle–Damgård hash absorbs the message in 64-byte blocks, and the final
digest *is* the internal state after the last block. So if you know
`H(secret ‖ data)`, you know the machine's exact state at that point. You can
reload that state, keep hashing, and produce a valid digest for a **longer**
message — one whose middle contains the padding the original hash added:

```
forged message  =  data ‖ glue-padding ‖ append
new digest      =  H(secret ‖ data ‖ glue-padding ‖ append)
```

The only unknown you need is `len(secret)`, because the glue-padding's contents
(a `0x80` byte, zeros, and the bit-length) depend on it. When you don't know it,
sweep a range and try each forgery against the oracle.

`hashlib` cannot resume a hash from a digest, so AESOP carries small pure-Python
MD5 and SHA-1 implementations whose internal registers can be seeded directly
from the known digest.

### Using AESOP

```console
# You captured a valid (message, MAC) pair and know the secret is 16 bytes:
$ aesop length-extension \
    --algo md5 \
    --hash 8f... \
    --data 'user=guest&role=user' \
    --append '&role=admin' \
    --keylen 16
<forged message, hex>
<new digest>
       length-extension forgery
  algorithm               md5
  assumed secret length   16
  forged message len      59 bytes
  glue padding            23 bytes
  new digest              <hex>

# Don't know the secret length? Sweep a range — one row will verify:
$ aesop length-extension --algo sha1 --hash <H> \
    --data '...' --append '&admin=true' --keylen 8-32
```

The forged message is emitted as **hex** (it contains non-printable padding
bytes); feed it to the target after your own decode. For a range, each line is
`keylen⇥forged-hex⇥new-digest`.

### Defence

- Use **HMAC** (`H(key ‖ H(key ‖ msg))` with proper padding) — it is immune.
- Or use a hash that isn't length-extendable: **SHA-3/Keccak**, or the truncated
  **SHA-512/256** and **BLAKE2**.

---

## Options

### `hash-id` / `crack`
| flag | meaning |
|------|---------|
| positional | the digest (hex, or `$`-prefixed crypt string for `hash-id`) |
| `-a, --algo` | (`crack`) hash algorithm; inferred from length if omitted |
| `-w, --wordlist PATH` | (`crack`) wordlist; default `/usr/share/dict/words` |
| `--no-mutations` | (`crack`) try each word verbatim only |
| `--max N` | (`crack`) stop after *N* candidates (`0` = no cap) |

### `hash`
| flag | meaning |
|------|---------|
| `-a, --algo NAME` | emit only this algorithm's digest (`out.raw`) |
| `--all` | show every supported algorithm |
| `-f, --file` / `-e, --in-encoding` | standard AESOP input handling |

### `length-extension`
| flag | meaning |
|------|---------|
| `--algo md5\|sha1` | the Merkle–Damgård hash to attack (default md5) |
| `--hash HEX` | the known digest `H(secret ‖ data)` |
| `--data` | the known message bytes that followed the secret |
| `--append` | the bytes you want to append |
| `--keylen` | secret length `N`, a range `8-16`, or a list `8,12,16` |

---

## When to reach for each

- **A hex blob and no idea what it is** → `hash-id`, then `aesop identify` for
  the surrounding data.
- **Need a checksum or to reproduce a known hash** → `hash`.
- **A leaked unsalted digest of a likely-weak password** → `crack`.
- **A homemade `H(secret ‖ msg)` MAC over MD5/SHA-1/SHA-256** → `length-extension`.

## See also

- `aesop manual getting-started` — input handling, pipes and encodings.
- `aesop identify` — triage an unknown blob before you touch it.
- `aesop manual rsa` — the number-theoretic attacks in the modern group.
- `aesop manual xor` — the other everyday building block of modern schemes.

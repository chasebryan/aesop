# Predictable PRNGs — MT19937 & LCG
> Watch the storyteller long enough and the trick gives itself away. A statistical generator is a fable of randomness; enough of its output is the whole plot.

## The fable

In *The Fox and the Cat*, the cat knows one trick and the fox boasts a hundred —
but the fox's tricks are all variations he performs in the open, and the hounds
learn them. A non-cryptographic PRNG is that fox: fast, clever, endlessly
productive, and utterly predictable to anyone who has watched the routine. The
cat's single, secret trick is `secrets` / `os.urandom` — and this page does not
break that one.

## What this breaks (and what it does not)

| Generator | Where you meet it | Breakable here? |
|-----------|-------------------|-----------------|
| **MT19937** (Mersenne Twister) | Python `random`, PHP `mt_rand`, NumPy legacy, games, tokens | Yes — clone from 624 outputs |
| **LCG** (linear congruential) | C `rand()`, `java.util.Random`, glibc `random`, toys | Yes — recover `a, c, m` |
| **CSPRNG** | `secrets`, `os.urandom`, `/dev/urandom`, `getrandom(2)` | **No** — by design |

If a token, session id, shuffle, coupon code, or "random" nonce was drawn from
`random` instead of `secrets`, it is deterministic once you have seen enough of
the stream.

## MT19937 — how it works

MT19937 keeps an internal array of **624** 32-bit words. It never hands you a
state word directly; it passes each through an invertible scrambler called
**tempering**:

```
y  = x
y ^= (y >> 11)
y ^= (y << 7)  & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= (y >> 18)
output y
```

Every step is an xor with a shifted copy of the word, and every one is
reversible:

- An xor-*right*-shift leaves the top `s` bits untouched, so you peel the word
  from the **most-significant** end down.
- An xor-*left*-shift leaves the low `s` bits untouched, so you peel from the
  **least-significant** end up.

Undo the four steps in reverse order and you have recovered the raw state word
`x` from the output `y`. That is `untemper`.

### Breaking it

1. Collect **624 consecutive** 32-bit outputs (`getrandbits(32)` in Python).
2. `untemper` each one → the 624 internal state words.
3. Splice them into a fresh MT19937 and run it forward.

Because MT's recurrence is a *sliding window* over the state stream, **any** 624
consecutive outputs form a complete, valid state — you do not need to catch the
generator on a 624-boundary. From there, every future output is reproduced
*exactly*, bit for bit. AESOP's clone matches CPython's `random.getrandbits(32)`
precisely (you could equally `random.setstate` the recovered words).

Caveats worth knowing:

- You need **full 32-bit** outputs. Truncated draws (`randint(0, 99)`,
  `getrandbits(16)`) discard bits and need a heavier solver (a linear system
  over GF(2)) — out of scope here; AESOP will tell you if values are out of range.
- Seeding via `random.seed()` uses an init step, but recovery does not care how
  it was seeded — it reconstructs the *current* state.

## LCG — how it works

A linear congruential generator is a single line of arithmetic:

```
x_{n+1} = (a · x_n + c) mod m
```

The full state is one number. That is its downfall.

### Breaking it

Given consecutive outputs `s_0, s_1, s_2, …`:

1. **Modulus `m`.** Difference the sequence, `t_i = s_{i+1} − s_i`. The constant
   `c` cancels, leaving `t_{i+1} ≡ a·t_i (mod m)`. Therefore each 2×2 determinant

   ```
   u_i = t_{i+2}·t_i − t_{i+1}²
   ```

   is an exact multiple of `m`. Take `gcd(u_0, u_1, …)` over enough of them and
   it collapses to `m` (a handful of small spurious factors are stripped by
   checking that every output is `< m`).
2. **Multiplier `a`.** With `m` in hand,
   `a = (s_2 − s_1)·(s_1 − s_0)⁻¹ mod m`, using the first difference that is
   invertible modulo `m`.
3. **Increment `c`.** `c = (s_1 − a·s_0) mod m`.

Three consecutive outputs suffice when you already know `m`. When `m` is unknown
the `gcd` needs a few determinants to converge — and for a **power-of-two**
modulus it can overshoot by a factor of two, since the differences share extra
low-order factors of 2. So give **~10+** consecutive outputs for an unknown
modulus. AESOP does more than replay the fit: for an auto-recovered modulus it
**cross-validates** by re-deriving the parameters from all but the last few
outputs and checking they predict that held-out tail. If they do not, it refuses
to guess rather than emit confidently-wrong values, and asks for more data or a
known `--modulus`.

## Using AESOP

```console
# MT19937: clone from a file of 624+ getrandbits(32) values, predict 5 more
$ python3 -m aesop prng --mt -f outputs.txt --count 5

# Same, over a pipe (one integer per line, or a JSON array)
$ cat outputs.txt | aesop prng --mt --count 3

# LCG with a known modulus: three consecutive outputs are enough
$ aesop prng --lcg -m 2147483648 1250496027 1116302264 1000676753

# LCG, unknown modulus: give ~10+ consecutive outputs so m can be pinned
$ aesop prng --lcg -f lcg_stream.txt --count 8

# Let AESOP choose: 624+ values ⇒ MT, fewer ⇒ LCG
$ aesop prng -f mystery_stream.txt
```

Predicted values are printed with `out.raw`, one per line, so they flow straight
into whatever comes next:

```console
$ aesop prng --mt -f outputs.txt --count 1 | xargs ./guess_the_token
```

### Options

| flag | meaning |
|------|---------|
| `--mt` | MT19937 mode — clone the state from 624+ 32-bit outputs. |
| `--lcg` | LCG mode — recover `a, c, m` from consecutive outputs. |
| `-n, --count N` | How many future values to predict (default 10). |
| `-m, --modulus M` | Known LCG modulus; skips modulus recovery. |
| `-f, --file PATH` | Read outputs from a file (line-per-value, CSV, or JSON array). |
| `OUTPUT …` | Outputs as positional integers (decimal or `0x`/`0o`/`0b`). |

With neither `--mt` nor `--lcg`, AESOP auto-selects: 624 or more outputs are
treated as an MT19937 clone, fewer as an LCG.

## When to reach for it

- A token, nonce, password-reset code, shuffle or "random" pick looks
  guessable, and the source used `random`, `mt_rand`, `rand()` or
  `java.util.Random` rather than a CSPRNG.
- You can observe a run of consecutive outputs (a leaderboard of draws, a series
  of ids, a debug log of the generator).
- A CTF challenge hands you exactly 624 numbers, or a stream and asks for "the
  next one".

If your outputs are **truncated** (small ranges, fewer than 32 bits), MT cloning
does not apply directly — you need a GF(2) linear solve over the tempering and
twist. If the numbers look uniformly random with no short recurrence, suspect a
real CSPRNG and stop: there is nothing to recover.

## See also

- `aesop manual rsa` — the other place "just use the secure primitive" is the
  whole lesson.
- `aesop manual entropy` — is this stream random-looking at all? (`aesop entropy`)
- `aesop manual scoring` — measuring structure vs. randomness.

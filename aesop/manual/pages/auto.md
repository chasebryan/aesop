# Auto — the one-command solver
> Hand it a mystery and walk away. Auto identifies, decodes, and breaks — recursively — until the truth falls out.

## The fable

*The Tortoise and the Hare* rewards steady, methodical work over flashy speed.
`auto` is the tortoise: it doesn't guess wildly, it works the problem in order —
triage, decode, break, repeat — and it gets there.

## What it does

`auto` is the orchestrator that ties the whole workbench together. Given an
unknown input it runs a pipeline:

1. **Identify.** Uses the same engine as `aesop identify` (entropy, Index of
   Coincidence, character set, structure) to form ranked hypotheses.
2. **Decode layers.** If the data looks like an *encoding* (base64, hex, base32,
   gzip, …), it peels it — reusing the `magic` search — and re-identifies the
   result. This repeats, so `hex(base64(text))` is unwrapped in one go.
3. **Break ciphers.** When the data looks like a *cipher*, it dispatches to the
   right solver:
   - monoalphabetic / plaintext → `caesar`, then `substitution`
   - IC in the Vigenère band → `vigenere`
   - non-text / binary → `xor` (single- and repeating-key)
   - and so on.
4. **Recurse & stop.** Each solved layer is fed back in. The search halts when it
   reaches readable English or a result matching the flag pattern.

The output is the recovered text plus the **chain of steps** that got there, so
you can understand and reproduce the solution.

## Using AESOP

```console
# A shift cipher
$ aesop auto 'Uryyb, jbeyq!'

# A layered encoding
$ aesop auto 'NBSWY3DPEB3W64TMMQ======'

# From a file, hunting a specific flag format
$ aesop auto -f challenge.txt --flag-format 'CTF\{.*\}'
```

### Options

| flag | meaning |
|------|---------|
| `--flag-format REGEX` | Stop as soon as output matches this (default `word{...}`). |
| `--depth N` | How many layers/steps to attempt. |
| `--top K` | Show K candidate solution chains. |
| `-f, --file` | Read the input from a file. |

## When to reach for it — and when not

`auto` is the right first move when you **don't know** what you have, or the
challenge is a straightforward stack of well-known transforms. It favours breadth
over depth.

Reach for the **specific** command when:

- you already know the cipher (`aesop vigenere`, `aesop rsa`, …) and want full
  control over parameters;
- the cipher needs external input `auto` can't supply (an RSA modulus, a padding
  oracle endpoint, a known-plaintext pair for Hill);
- `auto` gets close but a solver needs tuning (more restarts, a forced key
  length).

Think of `auto` as the fox's first pounce, and the named commands as the careful
follow-through.

## See also

- `aesop manual magic` — the encoding-only auto-decoder `auto` builds on.
- `aesop manual identify` — the triage step, on its own.
- `aesop manual getting-started` — the overall workflow.

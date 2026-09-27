# Getting Started with AESOP
> The five-minute tour: how to point AESOP at a mystery and let the fox do the work.

## The idea

AESOP is a **workbench**: one command, many tools, a manual for each. You bring
a ciphertext or a suspicious blob; AESOP helps you figure out what it is and
break it. Three things make it pleasant:

1. **It reads your input however you have it.** A literal string, a file
   (`-f path`), or a pipe (`echo ... | aesop ...`). It auto-detects hex and
   base64; force it with `-e raw|hex|base64|base64url` if it guesses wrong.
2. **Results go to stdout, cleanly.** So you can pipe one command into another.
3. **Every command has `-h` and a `manual`.** `aesop manual <topic>`.

## The first move: triage

If you don't know what you have, ask:

```console
$ aesop identify -f mystery.txt     # reasoned guess + what to try next
$ aesop entropy  -f mystery.bin     # random-looking? structured?
$ aesop freq     -f cipher.txt      # letter stats, Index of Coincidence, Kasiski
```

The **Index of Coincidence** (from `freq`) is your compass for text ciphers:

| IC (letters) | likely cipher | try |
|--------------|---------------|-----|
| ~0.066 | monoalphabetic (or plaintext) | `caesar`, then `substitution` |
| ~0.045–0.06 | polyalphabetic, short key | `vigenere` |
| ~0.038 | long-key polyalphabetic / random | `xor`, deeper analysis |

See `aesop manual scoring` for the maths.

## The lazy move: let it solve

```console
$ aesop auto 'Uryyb, jbeyq!'
$ aesop auto 'NBSWY3DPEB3W64TMMQ======'
$ aesop magic -f blob.txt          # for layered *encodings* specifically
```

`auto` runs `identify`, decodes any encoding layers, and dispatches to the right
solver — recursively — stopping when it finds readable text or a flag.

## The precise move: name the technique

When you know (or suspect) the cipher, call it directly for full control:

```console
$ aesop vigenere --key-length 5 -f cipher.txt
$ aesop rsa -n <N> -e 65537 -c <C> --attack wiener
$ aesop xor --repeating -f cipher.bin
```

## Working with encodings

```console
$ aesop b64 -d 'aGVsbG8='          # decode
$ echo -n 'hello' | aesop hex       # encode
$ aesop b58 -d '2NEpo7TZRRrLZSi2U'  # base58, and friends: b32, b85, binary, url
```

## Interactive mode

```console
$ aesop repl
aesop » caesar 'Wkh txlfn eurzq ira'
aesop » manual vigenere
aesop » quit
```

## Where to go next

- `aesop manual scoring` — how "looks like English" is measured (the engine
  behind every automatic solver).
- `aesop manual caesar` / `vigenere` / `substitution` — the classical core.
- `aesop manual rsa` — the modern math attacks.
- `aesop manual auto` / `magic` — the automation.
- `aesop list` — everything, at a glance.

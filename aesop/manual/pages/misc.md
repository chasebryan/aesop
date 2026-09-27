# Fixed Alphabets — Atbash, ROT47, Morse, Bacon, A1Z26 & Reverse
> A drawer of small, keyless transforms. None of them hides much; the whole trick is knowing which one you are looking at.

## The fable

The fox in Aesop's tales rarely wins by strength — he wins by *recognition*. He
sees a trap for a trap and a disguise for a disguise. These six schemes are the
disguises that fool no one who has seen them before: a mirror, a rotation, a
tapping of dots, two typefaces, a column of numbers, a word walked backwards.
Learn their faces once and they never fool you again.

None of them has a key worth searching. There is nothing to *break* — only to
*identify* and *undo*. That is exactly why they show up as the first or last
layer of so many multi-stage puzzles: they are cheap to apply and, to the
untrained eye, opaque.

---

## `atbash` — the mirror alphabet

### How it works

Atbash (from the Hebrew letters *aleph-taw-beth-shin*) is the fixed
substitution that reflects the alphabet end for end:

```
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Z Y X W V U T S R Q P O N M L K J I H G F E D C B A
```

Formally `c = 25 − p` on letter indices. It is a special case of the Affine
cipher (`a = 25, b = 25`) and, like every reflection, it is an **involution**:
apply it twice and you are back where you started, so a single pass both encodes
and decodes.

### Using AESOP

```console
$ aesop atbash 'HELLO'
SVOOL
$ aesop atbash 'SVOOL'            # the same command decodes
HELLO
$ echo 'Gsv jfrxp yildm ulc' | aesop atbash
The quick brown fox
```

Case and non-letters are preserved. There are no options beyond the standard
input trio.

---

## `rot47` — ROT13 for the whole keyboard

### How it works

ROT13 rotates the 26 letters by 13. **ROT47** does the same thing over the 94
*printable* ASCII characters (codepoints 33–126, `!` through `~`), so it also
scrambles digits and punctuation:

```
c = 33 + ((p − 33) + 47) mod 94
```

Because the alphabet has 94 symbols and the rotation is exactly half of that,
ROT47 — like ROT13 — is its **own inverse**. Space (code 32) and control
characters are left untouched, so line structure survives.

### Using AESOP

```console
$ aesop rot47 'Hello, World!'
w6==@[ (@C=5P
$ aesop rot47 'w6==@[ (@C=5P'    # self-inverse: same command decodes
Hello, World!
```

### When to reach for it

You see a string of dense, "keyboard-soup" punctuation and digits with the same
length as the expected plaintext, often as a CTF's outer wrapper. If only the
*letters* look shifted and spaces/digits are intact, reach for
`aesop caesar` (ROT13 is `-n 13`) instead.

---

## `morse` — International Morse code

### How it works

Morse encodes each character as a sequence of short marks (`.`, "dit") and long
marks (`-`, "dah"). AESOP uses the International standard and covers the 26
letters, the 10 digits and the common punctuation set. The convention for
spacing:

- **within a letter** — no separator (the marks are contiguous);
- **between letters** — one space;
- **between words** — a slash `/`.

So `SOS` (`S=...`, `O=---`) becomes `... --- ...`.

### Breaking / decoding it

There is no key. Decoding is a straight table lookup once you have split the
stream on its separators. AESOP's decoder is lenient about spacing around the
word slash and ignores any symbol it does not recognise.

### Using AESOP

```console
$ aesop morse 'SOS'
... --- ...
$ aesop morse 'HELLO WORLD'
.... . .-.. .-.. --- / .-- --- .-. .-.. -..
$ aesop morse -d '... --- ...'
SOS
$ echo '.... . .-.. .-.. ---' | aesop morse -d
HELLO
```

| flag | meaning |
|------|---------|
| `-d, --decode` | Decode Morse back to text (default direction is encode). |

---

## `bacon` — Bacon's biliteral cipher

### How it works

Francis Bacon's 1605 cipher assigns each letter a **five-symbol** code drawn
from a two-letter alphabet (here written `A`/`B`), i.e. five bits per letter:

```
A = AAAAA   B = AAAAB   C = AAABA   ...   Z = BBAAB   (26-letter variant)
```

Historically it was **steganographic**: the two symbols were hidden in a
*typeface* (roman vs. italic) or letter-case of an innocent cover text, so the
message was concealed rather than merely scrambled.

AESOP supports both forms:

- **26-letter (default)** — every letter has a distinct code; round-trips
  losslessly.
- **24-letter (classic)** — as Bacon published it, **I** shares J's code and
  **U** shares V's, so those pairs cannot be distinguished on decode.

### Using AESOP

```console
$ aesop bacon 'HELLO'
AABBB AABAA ABABB ABABB ABBBA
$ aesop bacon -d 'AABBB AABAA ABABB ABABB ABBBA'
HELLO
$ aesop bacon --variant 24 'JULIUS'
$ echo '00010 00000 00010' | aesop bacon -d     # 0/1 accepted for A/B
```

On decode, `0`/`1` are accepted as aliases for `A`/`B` and every other character
(spaces, punctuation, cover text) is ignored, so you can paste a raw bit stream
straight in.

| flag | meaning |
|------|---------|
| `-d, --decode` | Decode an A/B (or 0/1) stream back to text. |
| `--variant {24,26}` | Alphabet variant; `26` (default) is lossless, `24` is the classic I=J, U=V form. |

---

## `a1z26` — letters as numbers

### How it works

The simplest "cipher" of all: replace each letter by its position in the
alphabet, `A=1 … Z=26`. AESOP joins the numbers within a word with a chosen
separator and separates words with `/`.

### Using AESOP

```console
$ aesop a1z26 'HELLO'
8 5 12 12 15
$ aesop a1z26 -d '8 5 12 12 15'
HELLO
$ aesop a1z26 --sep - 'HELLO WORLD'
8-5-12-12-15 / 23-15-18-12-4
$ echo '8 5 12 12 15' | aesop a1z26 -d
HELLO
```

Decoding is **separator-agnostic**: it extracts every run of digits, so whatever
delimiter was used on encode (space, dash, comma, dot) round-trips. Numbers
outside 1–26 are rejected with an error.

| flag | meaning |
|------|---------|
| `-d, --decode` | Decode numbers back to letters (default is encode). |
| `-s, --sep S` | Separator placed between numbers on encode (default: space). |

> **Heads-up on encodings.** A stream like `8 5 12 12 15` is also valid
> hexadecimal, so AESOP deliberately does *not* run this command's input through
> the usual hex/base64 auto-detector — it is always treated as literal text.

---

## `reverse` — walk the string backwards

### How it works

Reverse the order of every character. Trivial, self-inverse, and a favourite
inner or outer layer in puzzle chains — a base64 blob printed backwards, a flag
written right-to-left.

```console
$ aesop reverse 'HELLO'
OLLEH
$ aesop reverse 'nwad ta kcattA'
Attack at dawn
$ echo 'reverse me' | aesop reverse
em esrever
```

---

## When to reach for this page

- Short, keyless-looking transforms; the ciphertext length matches the
  plaintext and no frequency analysis is needed.
- A challenge names one of these by hint ("morse", "biliteral", "A=1", "mirror",
  "ROT47") or shows its tell-tale shape (dots and dashes; runs of `A`/`B`;
  columns of numbers 1–26; keyboard-soup punctuation).
- You are peeling one layer of a multi-stage puzzle. Chain AESOP commands with
  pipes:

  ```console
  $ echo 'SVOOL' | aesop atbash | aesop reverse
  ```

## See also

- `aesop manual caesar` — Atbash's cousin; ROT13 is the letters-only ROT47.
- `aesop manual affine` — Atbash is the Affine key `a=25, b=25`.
- `aesop manual scoring` — how "looks like English" is measured, once you have
  peeled these layers off.
- `aesop manual magic` / `aesop magic` — throw an unknown blob at the detector
  when you are not sure which disguise you are facing.

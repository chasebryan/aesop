<!-- AESOP — the cryptanalyst's book of fables -->
```
    /\_/\     AESOP
   ( o.o )    Analytic Encryption-Solving Oracle Platform
    > ^ <     the cryptanalyst's book of fables
```

# AESOP

**An all-in-one cryptanalysis workbench for CTF, security research and teaching.**

Every ciphertext, like every fable, hides a truth beneath its surface — and the
clever fox always finds it. AESOP bundles the classical ciphers, the textbook
modern attacks, the encoding zoo, and the analysis tools you actually reach for,
behind one friendly command with a **built-in field guide** for every technique.

> **Scope & ethics.** AESOP is built for capture-the-flag competitions,
> coursework, self-study and analysing systems you are authorised to test. It
> implements *well-known, published* techniques (the same ones in any
> cryptography course or tool like CyberChef / RsaCtfTool). Use it on data and
> systems you own or have permission to assess.

---

## Why AESOP

- **Easy by default, deep on demand.** `aesop auto <blob>` just solves it. Every
  technique also has its own precise command and a `-h` and a manual page.
- **It guesses your input.** Hex, base64, a file, or a pipe — AESOP figures it
  out (and you can always override with `-e`).
- **A teacher, not just a tool.** `aesop manual <topic>` explains the *theory*,
  *when to use it*, and *how* — right in your terminal.
- **Honest about power-ups.** Works with just the standard library + `rich`;
  `aesop version` shows which optional accelerators (sympy, pycryptodome, …) are
  active.
- **Composable.** Every command prints its primary result cleanly to stdout, so
  you can pipe stages together like Unix tools.
- **A graphical workbench, too.** `aesop gui` opens every command as a form,
  with live charts of your input and results you can click back into the next
  step — no extra dependencies.

---

## Install

```bash
# from the project directory — creates .venv and installs everything
./install.sh               # or: ./install.sh core   (needs only 'rich')
source .venv/bin/activate

# or by hand
python3 -m venv .venv && source .venv/bin/activate
pip install -e .           # core (needs only 'rich')
pip install -e ".[full]"   # + sympy, pycryptodome, cryptography, numpy, scapy, … (recommended)

# or run without installing
python3 -m aesop <command>
```

Install into a virtual environment, as above: Debian, Ubuntu and other modern
distros refuse a system-wide `pip install` with `error:
externally-managed-environment` (PEP 668).

Then:

```bash
aesop version      # banner + capabilities
aesop list         # the full command catalogue
aesop manual       # the field guide index
aesop gui          # the graphical workbench
```

---

## Quick tour

```bash
# "Just solve it" — identify + decode + break, recursively
aesop auto 'Uryyb, jbeyq!'
aesop auto 'NBSWY3DPEB3W64TMMQ======'

# Classical
aesop caesar 'Wkh txlfn eurzq ira'
aesop vigenere 'LXFOPVEFRNHR'                 # auto key-length + key
aesop substitution -f secret.txt              # hill-climbing solver
aesop xor -f cipher.bin                        # single- & repeating-key XOR

# Encodings
echo 'ZmxhZ3tuZXN0ZWR9' | aesop magic          # peel nested layers
aesop b64 -d 'aGVsbG8='

# Modern / math
aesop rsa -n 0x... -e 65537 -c 0x... --attack auto
aesop hash-id 5f4dcc3b5aa765d61d8327deb882cf99
aesop prng --mt -f mt_outputs.txt --count 5    # predict MT19937

# Analysis
aesop identify -f mystery.bin                   # what am I looking at?
aesop freq -f cipher.txt                        # frequencies, IC, Kasiski
aesop entropy -f blob.bin                        # entropy map
```

---

## The workbench

```bash
aesop gui                  # reopen where you left off
aesop gui vigenere         # open on a particular command
aesop gui --theme light    # dark is the default
```

A desktop window over the same commands as the CLI:

- **Every command is a form**, generated from the command registry — so the
  options always match the CLI, and a command you add appears on its own. The
  equivalent command line is shown as you fill it in.
- **One input, many tools.** The input box persists as you switch commands, and
  any result (or table cell) can be sent back into it, so
  identify → decode → break stays in one place.
- **An inspector** charts the input as you type: entropy, Index of
  Coincidence, letter frequencies against English, byte distribution, and
  entropy along a file.
- **The field guide, clickable**, plus a history of every run in the session.
- **Long solvers can be stopped.** Commands run in a separate worker process;
  the window never freezes, and nothing listens on the network.

It uses Tkinter from the standard library. If your Python lacks it, install
your platform's Tk bindings (`sudo apt install python3-tk` on Debian/Ubuntu).
See `aesop manual gui` for the full tour and keyboard shortcuts.

---

## The catalogue

`aesop list` is always the source of truth. The map:

### Analysis & triage
| command | what it does |
|---------|--------------|
| `auto` | Identify, then decode/break automatically (the flagship). |
| `identify` | Reasoned guess of cipher/encoding, with next-step suggestions. |
| `freq` | Letter/byte frequencies, Index of Coincidence, χ², n-grams, Kasiski. |
| `entropy` | Shannon entropy overall and across a sliding window. |

### Classical ciphers
| command | what it does |
|---------|--------------|
| `caesar` | Caesar / ROT-n shift — brute force + language scoring. |
| `vigenere` | Repeating-key polyalphabetic — Friedman/Kasiski + χ² key recovery. |
| `substitution` | Monoalphabetic substitution — quadgram hill-climbing. |
| `affine` | Affine cipher — brute force over valid (a, b). |
| `transposition` | Rail-fence and columnar transposition. |
| `xor` | Single-byte and repeating-key XOR (the cryptopals classics). |
| `playfair` | Playfair digraph cipher — annealing solver. |
| `hill` | Hill cipher — encrypt/decrypt + known-plaintext key recovery. |
| `atbash` `rot47` `morse` `bacon` `a1z26` `reverse` | Fixed alphabets & codes. |

### Modern & math attacks
| command | what it does |
|---------|--------------|
| `rsa` | Textbook RSA attacks: Fermat, Wiener, Pollard p−1/ρ, low-e, Håstad, common-modulus, common-factor. |
| `blockcipher` | ECB detection, CBC bit-flipping, padding-oracle decryption. |
| `hash-id` / `hash` / `crack` | Identify, compute, and dictionary-crack hashes. |
| `length-extension` | Merkle–Damgård length-extension for MD5/SHA1. |
| `prng` | MT19937 state recovery & prediction; LCG parameter recovery. |

### Encodings & formats
| command | what it does |
|---------|--------------|
| `magic` | Auto-detect and peel nested encodings (CyberChef-style). |
| `b64` `b32` `b58` `b85` `hex` `binary` `url` | The encoding zoo, encode & decode. |

### Reference & tooling
| command | what it does |
|---------|--------------|
| `manual` | The built-in field guide: `aesop manual <topic>`. |
| `list` | This catalogue. |
| `repl` | Interactive session with history & completion. |
| `gui` | The graphical workbench: forms, charts, clickable results. |
| `version` | Version + which optional accelerators are installed. |

---

## Design

AESOP is a small, well-factored Python package:

```
aesop/
  core/      number theory, scoring (quadgrams/IC/χ²/entropy), smart I/O, detection
  classical/ shift, vigenere, substitution, affine, transposition, xor, playfair, hill, …
  modern/    rsa, blockcipher, hashes, prng
  encoding/  bases, magic
  analysis/  identify, freq, entropy, auto
  network/   pcap
  manual/    the field-guide markdown pages
  gui/       the workbench: forms, renderer, charts, worker process
  registry, cli, ui, capabilities, repl
```

Two rules keep it clean and hackable:

1. **Every capability is a plug-in `Command`** registered with a decorator; the
   CLI builds itself from the registry. Adding a technique never means editing a
   central switchboard — drop in a module.
2. **Algorithms are separated from presentation.** Each module exposes a pure,
   importable API (great for scripting and testing) plus a thin CLI handler.

So you can also use AESOP as a library:

```python
from aesop.classical.caesar import solve
from aesop.core.score import index_of_coincidence

print(solve("Wkh txlfn eurzq ira")[0])   # (23, 'The quick brown fox', score)
```

---

## Extending AESOP

Add a file under the right subpackage, expose your algorithm as functions, and
register a command:

```python
from aesop.registry import command, arg, io_args
from aesop.core import io

@command("mycipher", group="classical", summary="…", manual="mycipher",
         args=io_args() + [arg("-k --key", "the key")])
def cmd_mycipher(args, out):
    inp = io.load(args)
    out.raw(solve(inp.text))
    return 0
```

Add `aesop.classical.mycipher` to the module list in `cli.py`, drop a
`manual/pages/mycipher.md`, and you're done. See `aesop/classical/caesar.py` for
the canonical example.

---

## Tests

```bash
pip install -e ".[full,dev]"   # inside the virtual environment
pytest
```

## License

Apache2.0

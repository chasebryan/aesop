# AESOP Cheatsheet

A one-page field reference. `aesop manual <topic>` for the full guide on any of these.

## Input, three ways (every data command)
```
aesop <cmd> 'literal text'            # inline
aesop <cmd> -f path/to/file           # from a file
echo data | aesop <cmd>               # from a pipe
aesop <cmd> -e hex|base64|raw ...     # force input decoding (default: auto)
```
Auto-detect rule: **letters-only → raw text**; hex/base64 need a digit or `+/=_-` tell.

## Don't know what it is?
```
aesop identify <blob>     # reasoned guess + next step
aesop entropy  <blob>     # ~8.0 = encrypted/compressed; ~4 = text
aesop freq     <text>     # letter stats, Index of Coincidence, Kasiski
aesop auto     <blob>     # just solve it (identify -> decode -> break)
aesop magic    <blob>     # peel nested *encodings* only
```

### Index of Coincidence → cipher family
| IC ≈ | family | command |
|------|--------|---------|
| 0.066 | monoalphabetic / plaintext | `caesar`, `substitution` |
| 0.045–0.06 | Vigenère (short key) | `vigenere` |
| 0.038 | long-key / random | `xor` |

## Classical
```
aesop caesar <text>                    # auto-solve; --all for ROT table
aesop caesar --encode -n 13 <text>     # ROT13 encode
aesop vigenere <text>                  # auto key-length + key
aesop vigenere -k KEY --encode <text>
aesop substitution <text>              # hill-climb; -k KEY26 to apply
aesop affine <text>                    # brute (a,b); -a 5 -b 8 --encode
aesop transposition <text>             # --type rail|columnar|auto
aesop xor <blob>                       # single & repeating key auto
aesop xor -k KEY --key-type ascii|hex  # apply XOR
aesop playfair <text> [-k KEY]
aesop hill --key '3,3,2,5' --size 2 --decode <text>
aesop atbash|rot47|morse|bacon|a1z26|reverse <text>
```

## Encodings
```
aesop b64 [-d] [--url] <data>
aesop b32|b58|b85|hex|binary|url [-d] <data>
```

## Modern / math
```
aesop rsa -n N -e E -c C --attack auto        # fermat|wiener|pollard-*|lowe|
                                              # hastad|common-modulus|common-factor
aesop hash-id <digest>                          # what hash is this?
aesop hash --algo sha256 <data>                 # compute
aesop crack --algo md5 <digest> [--wordlist W]  # dictionary attack
aesop length-extension --algo sha1 --hash H --data D --append A --keylen N
aesop blockcipher --ecb-detect <ciphertext>
aesop blockcipher --oracle './oracle {}' <ciphertext>   # padding oracle
aesop prng --mt -f outputs.txt --count 5        # predict MT19937
aesop prng --lcg -f seq.txt
```

## Meta
```
aesop list           # all commands       aesop manual [topic]   # field guide
aesop repl           # interactive        aesop version          # capabilities
aesop gui [command]  # graphical workbench (Ctrl+Enter run, Esc stop, Ctrl+U chain result)
aesop <cmd> -h       # per-command help
```

## As a library
```python
from aesop.classical.caesar import solve
from aesop.classical.xor import break_repeating
from aesop.core.score import index_of_coincidence, score_text
```

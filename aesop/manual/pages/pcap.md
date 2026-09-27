# PCAP — Packet-Capture Forensics & Crypto Triage
> Turns a capture into a case report: who left the network, what crossed the wire in the clear, what's encrypted, and what's still needed for the flag.

## The fable

In *The Wolf in Sheep's Clothing*, the danger is the one that blends in with the
flock. Network forensics is the shepherd's count: most packets are ordinary, but
a few — a lookalike hostname, a steady callback to a stranger — are the wolf.

## What it does

`aesop pcap <capture>` reads a `.pcap`/`.pcapng` and produces a structured
report:

1. **Overview** — packets, duration, hosts, protocol mix.
2. **Findings** (ranked by severity):
   - **Exfil** — every conversation that left the local network, with byte
     counts (internal → external, resolved to a domain where possible).
   - **C2 / beaconing** — regular, low-jitter callbacks to an external host
     (the signature of automated command-and-control), and queries to
     suspicious-TLD domains.
   - **DNS anomalies** — typosquatted/lookalike internal hosts, and overlong
     labels that can carry base32/hex **DNS tunnelling**.
   - **Crypto** — high-entropy (encrypted) streams whose contents can't be read
     without a key.
   - **Voice** — probable RTP calls to extract and transcribe.
3. **Cleartext credentials** — HTTP Basic, POP3/IMAP/FTP `USER`/`PASS`, SMTP
   `AUTH LOGIN` (base64-decoded for you).
4. **Auto-decoded blobs** — base64/hex material found in cleartext payloads is
   run through AESOP's `magic` engine; anything that decodes to text or a flag is
   surfaced.
5. **Requirements to reach the flag** — when the answer isn't sitting in the
   capture, AESOP states exactly what is still needed (a cipher key, a spoken
   secret, an out-of-band artifact) so you know where to look next.

## Using AESOP

```console
# Full case report
$ aesop pcap challenge.pcap

# Focus views
$ aesop pcap challenge.pcap --endpoints      # conversation table (int vs EXT)
$ aesop pcap challenge.pcap --creds          # just the captured credentials
$ aesop pcap challenge.pcap --dns            # every DNS query + resolution

# Custom flag format, and carve cleartext HTTP objects for deeper analysis
$ aesop pcap challenge.pcap --flag-format 'CBC\{.*\}'
$ aesop pcap challenge.pcap --carve ./objects
$ aesop magic -f ./objects/http_10.0.0.5_80_0.bin
```

### Options

| flag | meaning |
|------|---------|
| `--endpoints` | Full conversation/endpoint table, external flows tagged `EXT`. |
| `--creds` | Show only cleartext credentials. |
| `--dns` | Full DNS query list with resolutions. |
| `--flag-format REGEX` | Pattern that marks a flag (default matches `flag{…}`, `CTF{…}`, `CBC{…}`, …). |
| `--carve DIR` | Extract cleartext HTTP response bodies into `DIR` for follow-up. |
| `--top N` | Rows per table. |

## Method notes

- **Internal vs external** is decided by RFC1918/loopback/link-local membership —
  *not* Python's `is_private`, which now folds the RFC 5737 documentation ranges
  (`198.51.100.0/24`, `203.0.113.0/24`) in with real private space. Those ranges
  are exactly the "external" hosts labs use for C2, so AESOP treats them as
  external.
- **Beacon detection** looks for ≥8 connections to the same `(dst, port)` with a
  regular interval (low jitter) — periodicity, not volume, is the tell.
- **Encrypted-stream detection** flags long streams with entropy > 7.3 bits/byte
  and little printable content. AESOP will not pretend to read them; it tells you
  a key is required.

## When to reach for it

- A CTF/forensics task hands you a capture and asks *what happened* or *find the
  flag*.
- You need a fast triage of an incident capture: compromised host, C2, exfil,
  leaked credentials.

For decodable material the report gives you the plaintext/flag directly; for
enciphered channels it hands you the requirement, then use `aesop xor`,
`aesop rsa`, `aesop auto`, or an offline decrypt once you have the key.

## See also

- `aesop manual auto` / `magic` — the decoders `pcap` feeds candidate blobs into.
- `aesop manual identify` — classify a carved blob on its own.
- `aesop manual xor` / `rsa` — break the payload once you recover the key.

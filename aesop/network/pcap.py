"""
aesop.network.pcap — packet-capture forensics & crypto triage.

Point AESOP at a ``.pcap``/``.pcapng`` and it produces a *case report*: who
talked to whom, which conversations left the building, what secrets crossed the
wire in the clear, which channels are encrypted (and therefore need a key), and
whatever base64/hex/flag material can be decoded on the spot with the rest of the
toolbox.

Design goal: given a capture, either **recover the answer** (when the data is
decodable) or **state precisely what is still required** to reach the flag (a
key, a passphrase, an out-of-band artifact).  A good analyst tool is honest
about the boundary between "solved" and "blocked on a missing key".

Parsing uses ``scapy`` (a pure-Python dependency).  Cleartext application
protocols (HTTP, POP3, SMTP, IMAP, FTP) are reassembled and mined directly, so
no external ``tshark`` is required — though it is used opportunistically if
present for a couple of extras.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..registry import command, arg
from ..capabilities import require
from ..core.score import shannon_entropy, printable_ratio

# Reasonable default: word{...} style flags plus common CTF prefixes.
DEFAULT_FLAG_RE = r"(?:flag|CTF|CBC|NSA|key|secret|FLAG)\{[^}\n]{1,200}\}"

# TLDs that are disproportionately abused / worth a second look in an .mil/.internal net.
_SUSPICIOUS_TLDS = {"biz", "top", "xyz", "info", "ru", "cn", "tk", "gq", "click",
                    "zip", "mov", "work", "rest", "fit", "loan"}


# --------------------------------------------------------------------------- #
# Report data model
# --------------------------------------------------------------------------- #
@dataclass
class Conversation:
    a: str
    b: str
    proto: str = ""
    packets: int = 0
    bytes: int = 0
    ports: set = field(default_factory=set)
    first: float = 0.0
    last: float = 0.0
    external: bool = False


@dataclass
class Finding:
    severity: str        # "high" | "medium" | "info"
    kind: str            # "credential" | "exfil" | "c2" | "dns" | "cleartext" | "crypto" | "voice"
    title: str
    detail: str
    suggest: str = ""


@dataclass
class DecodedBlob:
    where: str
    recipe: str
    preview: str
    is_flag: bool = False


@dataclass
class PcapReport:
    path: str
    packets: int = 0
    duration: float = 0.0
    start: float = 0.0
    protocols: Dict[str, int] = field(default_factory=dict)
    hosts: Dict[str, int] = field(default_factory=dict)      # ip -> bytes
    conversations: List[Conversation] = field(default_factory=list)
    dns_names: Dict[str, int] = field(default_factory=dict)  # name -> count
    dns_map: Dict[str, str] = field(default_factory=dict)    # name -> resolved ip
    credentials: List[Tuple[str, str, str]] = field(default_factory=list)  # (proto, cred, where)
    messages: List[Tuple[str, str]] = field(default_factory=list)  # (subject/summary, body)
    findings: List[Finding] = field(default_factory=list)
    decoded: List[DecodedBlob] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _is_private(ip: str) -> bool:
    """Is ``ip`` on the local network (for forensics: RFC1918 / loopback / link-local)?

    Deliberately does NOT use ``ipaddress.is_private``: modern Python folds the
    RFC 5737 documentation ranges (198.51.100.0/24, 203.0.113.0/24) into
    ``is_private``, but those are exactly the "external" hosts CTFs use for C2 —
    so we must treat them as external, not internal.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return True
    if addr.version == 4:
        return any(addr in net for net in _RFC1918)
    return addr.is_private


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _tld(name: str) -> str:
    parts = name.rstrip(".").split(".")
    return parts[-1].lower() if parts else ""


def _registrable(name: str) -> str:
    parts = name.rstrip(".").split(".")
    return ".".join(parts[-2:]).lower() if len(parts) >= 2 else name.lower()


# --------------------------------------------------------------------------- #
# Core analysis
# --------------------------------------------------------------------------- #
def analyze_pcap(path: str, *, flag_re: str = DEFAULT_FLAG_RE,
                 max_decode: int = 12) -> PcapReport:
    """Parse ``path`` and return a populated :class:`PcapReport`."""
    require("scapy", "pcap analysis")
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ARP, Raw  # type: ignore
    from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore

    report = PcapReport(path=path)
    flag_pat = re.compile(flag_re.encode("latin-1")) if flag_re else None

    conv: Dict[Tuple, Conversation] = {}
    host_bytes: Dict[str, int] = defaultdict(int)
    proto_count: Dict[str, int] = defaultdict(int)
    # TCP stream reassembly: (src,sport,dst,dport) -> list of payload bytes
    streams: Dict[Tuple, bytearray] = defaultdict(bytearray)
    # connection start times per (src,dst,dport) for beacon analysis
    conn_starts: Dict[Tuple, List[float]] = defaultdict(list)
    first_ts: Optional[float] = None
    last_ts: float = 0.0

    for pkt in PcapReader(path):
        report.packets += 1
        ts = float(getattr(pkt, "time", 0.0))
        if first_ts is None:
            first_ts = ts
        last_ts = ts

        if pkt.haslayer(ARP):
            proto_count["arp"] += 1

        ipl = None
        if pkt.haslayer(IP):
            ipl = pkt[IP]
        elif pkt.haslayer(IPv6):
            ipl = pkt[IPv6]
        if ipl is None:
            continue

        src, dst = ipl.src, ipl.dst
        size = len(pkt)
        host_bytes[src] += size
        host_bytes[dst] += size

        proto = "ip"
        sport = dport = None
        payload = b""
        if pkt.haslayer(TCP):
            proto = "tcp"
            t = pkt[TCP]
            sport, dport = int(t.sport), int(t.dport)
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                streams[(src, sport, dst, dport)] += payload
            # New connection (SYN without ACK)
            if t.flags & 0x02 and not (t.flags & 0x10):
                conn_starts[(src, dst, dport)].append(ts)
        elif pkt.haslayer(UDP):
            proto = "udp"
            u = pkt[UDP]
            sport, dport = int(u.sport), int(u.dport)
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)

        # DNS
        if pkt.haslayer(DNS):
            proto_count["dns"] += 1
            dnsl = pkt[DNS]
            if dnsl.qd is not None:
                try:
                    qname = dnsl.qd.qname.decode("latin-1").rstrip(".")
                    if qname:
                        report.dns_names[qname] = report.dns_names.get(qname, 0) + 1
                except Exception:
                    pass
            # answers → name/ip map
            for i in range(int(getattr(dnsl, "ancount", 0) or 0)):
                try:
                    rr = dnsl.an[i]
                    if getattr(rr, "type", None) == 1:  # A
                        nm = rr.rrname.decode("latin-1").rstrip(".")
                        report.dns_map[nm] = rr.rdata if isinstance(rr.rdata, str) else str(rr.rdata)
                except Exception:
                    break
        else:
            proto_count[proto] += 1

        # conversation accounting
        key = tuple(sorted([src, dst]))
        c = conv.get(key)
        if c is None:
            c = Conversation(a=key[0], b=key[1], first=ts)
            conv[key] = c
        c.packets += 1
        c.bytes += size
        c.last = ts
        if dport is not None:
            c.ports.add(dport)
        if not c.proto:
            c.proto = proto
        if not _is_private(src) or not _is_private(dst):
            c.external = True

    report.start = first_ts or 0.0
    report.duration = (last_ts - (first_ts or last_ts))
    report.protocols = dict(sorted(proto_count.items(), key=lambda kv: -kv[1]))
    report.hosts = dict(sorted(host_bytes.items(), key=lambda kv: -kv[1]))
    report.conversations = sorted(conv.values(), key=lambda c: -c.bytes)

    _analyze_cleartext(streams, report, flag_pat)
    _analyze_dns(report)
    _analyze_external(report, conn_starts)
    _hunt_blobs(streams, report, flag_pat, max_decode)
    _analyze_voice(report)
    _build_requirements(report)
    return report


# ---- cleartext protocol mining -------------------------------------------- #
def _analyze_cleartext(streams, report: PcapReport, flag_pat) -> None:
    from ..core.io import LoadedInput  # noqa: F401 (kept for parity)

    for (src, sport, dst, dport), data in streams.items():
        if not data:
            continue
        text = bytes(data).decode("latin-1", "replace")

        # HTTP Basic auth
        for m in re.finditer(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.I):
            try:
                cred = base64.b64decode(m.group(1)).decode("latin-1")
                report.credentials.append(("HTTP Basic", cred, f"{src}->{dst}:{dport}"))
            except Exception:
                pass

        # POP3 / IMAP / FTP USER+PASS
        u = re.search(r"(?im)^(?:USER|LOGIN)\s+(\S+)", text)
        p = re.search(r"(?im)^PASS\s+(\S+)", text)
        if u and p:
            report.credentials.append(
                (f"{'POP3' if dport in (110,) else 'cleartext'}",
                 f"{u.group(1)}:{p.group(1)}", f"{src}->{dst}:{dport}"))

        # SMTP AUTH LOGIN (base64 user/pass on their own lines after AUTH LOGIN)
        if re.search(r"(?i)AUTH\s+LOGIN", text):
            b64s = re.findall(r"(?m)^([A-Za-z0-9+/]{4,}={0,2})\s*$", text)
            creds = []
            for b in b64s[:2]:
                try:
                    creds.append(base64.b64decode(b).decode("latin-1"))
                except Exception:
                    pass
            if creds:
                report.credentials.append(("SMTP AUTH", " / ".join(creds), f"{src}->{dst}:{dport}"))

        # Email subjects (POP/SMTP/IMAP bodies)
        for m in re.finditer(r"(?im)^Subject:\s*(.+)$", text):
            subj = m.group(1).strip()
            # grab a short body snippet following a blank line
            report.messages.append((subj, ""))

        # HTTP request lines to catch external Host headers
        # (kept lightweight; full extraction available via --carve)


# ---- DNS anomaly analysis -------------------------------------------------- #
def _analyze_dns(report: PcapReport) -> None:
    names = list(report.dns_names)
    if not names:
        return
    # Establish the dominant internal base domain (most common registrable).
    reg_counts: Dict[str, int] = defaultdict(int)
    for n in names:
        reg_counts[_registrable(n)] += report.dns_names[n]
    internal_bases = {b for b, _ in sorted(reg_counts.items(), key=lambda kv: -kv[1])[:3]}

    for n in names:
        tld = _tld(n)
        reg = _registrable(n)
        # Suspicious TLD on a name that isn't the internal domain.
        if tld in _SUSPICIOUS_TLDS:
            ip = report.dns_map.get(n, "?")
            report.findings.append(Finding(
                "high", "c2", f"Suspicious external domain queried: {n}",
                f"Uncommon TLD .{tld} resolving to {ip}. Classic C2 / ransom-portal shape.",
                "aesop pcap <file> --endpoints   # see the flow to this host"))
        # Exfil-shaped handled below; typosquats handled once per pair afterwards.
        pass

    # Typosquat / lookalike pairs — report each unordered pair once, ranking the
    # rarer name as the likely impostor.
    seen_pairs = set()
    for n in names:
        for other in names:
            if other <= n:
                continue
            if 1 <= _levenshtein(n, other) <= 2 and _tld(n) == _tld(other):
                key = tuple(sorted((n, other)))
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                # the impostor is usually queried far less often
                cn, co = report.dns_names.get(n, 0), report.dns_names.get(other, 0)
                impostor, legit = (n, other) if cn <= co else (other, n)
                report.findings.append(Finding(
                    "high", "dns", f"Lookalike host pair: {impostor}  vs  {legit}",
                    f"Names differ by a 1–2 char edit ({impostor} queried {min(cn,co)}×, "
                    f"{legit} {max(cn,co)}×) — typosquatting to blend malicious traffic in.",
                    ""))
        # Exfil-shaped: many long / high-entropy labels under one domain.
        labels = n.split(".")
        long_labels = [l for l in labels if len(l) >= 20]
        if long_labels:
            report.findings.append(Finding(
                "medium", "dns", f"Possible DNS tunnelling/exfil: {n[:60]}…",
                "Overlong subdomain labels can carry base32/hex-encoded exfil.",
                "aesop from-base32 <label>   # try decoding a label"))


# ---- external / beacon analysis ------------------------------------------- #
def _analyze_external(report: PcapReport, conn_starts) -> None:
    ip_to_name = {v: k for k, v in report.dns_map.items()}
    ext = [c for c in report.conversations if c.external]
    for c in ext[:20]:
        # which side is external / internal?
        ext_ip = c.a if not _is_private(c.a) else c.b
        int_ip = c.b if ext_ip == c.a else c.a
        name = ip_to_name.get(ext_ip, "")
        label = f"{ext_ip}" + (f" ({name})" if name else "")
        ports = ", ".join(str(p) for p in sorted(c.ports)[:6]) or "?"
        report.findings.append(Finding(
            "medium" if c.bytes < 200_000 else "high", "exfil",
            f"Outbound: {int_ip} -> {label}",
            f"{c.bytes:,} bytes over {c.packets} packets; dst ports {ports}.",
            ""))

    # Beacon regularity: many connections to same (dst,dport) at regular intervals.
    for (src, dst, dport), starts in conn_starts.items():
        if _is_private(dst) or len(starts) < 6:
            continue
        starts = sorted(starts)
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        if not gaps:
            continue
        mean = statistics.mean(gaps)
        if mean <= 0:
            continue
        jitter = (statistics.pstdev(gaps) / mean) if len(gaps) > 1 else 0.0
        if len(starts) >= 8 and jitter < 0.5:
            name = ip_to_name.get(dst, "")
            report.findings.append(Finding(
                "high", "c2",
                f"Beaconing to {dst}{(' ('+name+')') if name else ''}:{dport}",
                f"{len(starts)} connections, ~{mean:.1f}s interval, jitter {jitter:.0%} "
                f"(regular callbacks — hallmark of automated C2).",
                ""))


# ---- crypto blob hunting & decoding --------------------------------------- #
def _hunt_blobs(streams, report: PcapReport, flag_pat, max_decode: int) -> None:
    from ..core.detect import identify
    from ..encoding.magic import magic

    # 1. Direct flag search across all cleartext payloads.
    seen_flags = set()
    for data in streams.values():
        if not data or printable_ratio(bytes(data)) < 0.3:
            continue
        if flag_pat:
            for m in flag_pat.finditer(bytes(data)):
                f = m.group(0).decode("latin-1")
                if f not in seen_flags:
                    seen_flags.add(f)
                    report.flags.append(f)

    # 2. Encrypted-channel detection (high-entropy streams that carry real data).
    hi_entropy = 0
    for (src, sport, dst, dport), data in streams.items():
        if len(data) < 512:
            continue
        ent = shannon_entropy(bytes(data)[:4096])
        if ent > 7.3 and printable_ratio(bytes(data)[:2048]) < 0.4:
            hi_entropy += 1
    if hi_entropy:
        report.findings.append(Finding(
            "high", "crypto",
            f"{hi_entropy} high-entropy (encrypted) stream(s) detected",
            "Payloads are ~random — TLS or a custom-encrypted channel. Content "
            "cannot be read without the session key / cipher key.",
            "recover the key (memory dump, key exchange, or a spoken/typed secret) "
            "then: aesop xor / aesop rsa / decrypt offline"))

    # 3. Decode candidate base64/hex blobs from cleartext, via magic.
    decoded = 0
    b64_re = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
    for (src, sport, dst, dport), data in streams.items():
        if decoded >= max_decode:
            break
        blob = bytes(data)
        if printable_ratio(blob) < 0.5:
            continue
        for m in b64_re.finditer(blob):
            if decoded >= max_decode:
                break
            cand = m.group(0)
            if len(cand) < 24:
                continue
            try:
                results = magic(cand, depth=4, flag_re=flag_pat.pattern.decode("latin-1") if flag_pat else None)
            except Exception:
                continue
            if not results or not results[0].recipe:
                continue
            top = results[0]
            if top.is_flag or (printable_ratio(top.data) > 0.9 and len(top.data) >= 6):
                preview = top.data.decode("latin-1", "replace")[:60].replace("\n", " ")
                report.decoded.append(DecodedBlob(
                    where=f"{src}->{dst}:{dport}", recipe=" → ".join(top.recipe),
                    preview=preview, is_flag=top.is_flag))
                if top.is_flag:
                    f = top.data.decode("latin-1", "replace")
                    if f not in seen_flags:
                        seen_flags.add(f)
                        report.flags.append(f)
                decoded += 1


# ---- voice / RTP detection ------------------------------------------------- #
def _analyze_voice(report: PcapReport) -> None:
    # Big internal UDP conversations with steady small packets ≈ RTP voice.
    for c in report.conversations:
        if c.external or c.proto != "udp":
            continue
        if c.bytes > 100_000 and c.packets > 500:
            report.findings.append(Finding(
                "info", "voice",
                f"Probable RTP voice call: {c.a} ↔ {c.b}",
                f"{c.bytes:,} bytes / {c.packets} packets of steady UDP — extract the "
                f"audio; a spoken key/passphrase or DTMF digits may be the secret.",
                "extract RTP to WAV (e.g. Wireshark: Telephony ▸ RTP ▸ Play Streams), "
                "then transcribe / decode DTMF"))
            break


# ---- requirements synthesis ----------------------------------------------- #
def _build_requirements(report: PcapReport) -> None:
    reqs: List[str] = []
    if report.flags:
        reqs.append("A flag is directly present/decodable in the capture (see Flags).")
    has_crypto = any(f.kind == "crypto" for f in report.findings)
    has_voice = any(f.kind == "voice" for f in report.findings)
    has_c2 = any(f.kind == "c2" for f in report.findings)
    if has_crypto:
        reqs.append("Encrypted channel present → recover the CIPHER/SESSION KEY "
                    "(from a memory dump, key exchange, or an out-of-band secret) to "
                    "decrypt the exfil and read the payload.")
    if has_voice:
        reqs.append("Voice/RTP call present → EXTRACT & TRANSCRIBE the audio "
                    "(spoken passphrase) and/or DECODE DTMF beeps to digits.")
    if has_c2:
        reqs.append("Identify the COMPROMISED HOST and the C2/exfil DESTINATION "
                    "(domain + IP) from the beaconing/external findings — often the "
                    "flag answer itself.")
    if report.credentials:
        reqs.append("Cleartext credentials were captured → they may unlock the mail "
                    "store, portal, or the next artifact.")
    if not reqs:
        reqs.append("No obvious lead surfaced automatically — carve files/streams "
                    "(--carve) and re-run auto-decode on the extracted objects.")
    report.requirements = reqs


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
_SEV_STYLE = {"high": "bold red", "medium": "yellow", "info": "cyan"}


@command(
    "pcap",
    group="network",
    summary="Forensic triage of a packet capture: endpoints, creds, exfil, crypto",
    manual="pcap",
    aliases=["pcapng"],
    args=[
        arg("file", "the .pcap / .pcapng capture to analyse", metavar="CAPTURE"),
        arg("--flag-format", "regex marking a flag", dest="flag_format", default=DEFAULT_FLAG_RE),
        arg("--endpoints", "show the full conversation/endpoint table", action="store_true"),
        arg("--creds", "show only captured cleartext credentials", action="store_true"),
        arg("--dns", "show the full DNS query list", action="store_true"),
        arg("--top", "how many rows in tables", type=int, default=12),
        arg("--carve", "directory to extract cleartext HTTP objects / streams into",
            metavar="DIR"),
    ],
    examples=[
        "aesop pcap challenge.pcap",
        "aesop pcap capture.pcapng --endpoints",
        "aesop pcap traffic.pcap --flag-format 'CBC\\{.*\\}'",
    ],
    description="""
        Turns a packet capture into a case report. It maps endpoints and flags
        traffic that left the network, extracts cleartext credentials and email,
        spots DNS anomalies (typosquats, suspicious TLDs, tunnelling), detects
        encrypted/beaconing C2 channels, and auto-decodes any base64/hex/flag
        material with AESOP's own engine. When the answer isn't directly
        recoverable it prints exactly what is still required (a key, a spoken
        secret, an out-of-band artifact) to reach the flag.
    """,
)
def cmd_pcap(args, out) -> int:
    import os
    if not os.path.exists(args.file):
        out.error(f"no such file: {args.file}")
        return 2
    try:
        report = analyze_pcap(args.file, flag_re=args.flag_format)
    except RuntimeError as exc:
        out.error(str(exc))
        return 1

    if args.creds:
        return _render_creds(report, out)
    if args.endpoints:
        return _render_endpoints(report, out, args.top)
    if args.dns:
        return _render_dns(report, out)
    if args.carve:
        _carve(args.file, args.carve, out)

    _render_report(report, out, args.top)
    return 0


def _render_report(report: PcapReport, out, top: int) -> None:
    out.rule("AESOP pcap case report")
    out.keyval([
        ("file", report.path),
        ("packets", f"{report.packets:,}"),
        ("duration", f"{report.duration:.1f} s"),
        ("hosts", len(report.hosts)),
        ("protocols", ", ".join(f"{k}:{v}" for k, v in list(report.protocols.items())[:8])),
    ], title="overview")

    # Findings, most severe first.
    order = {"high": 0, "medium": 1, "info": 2}
    findings = sorted(report.findings, key=lambda f: order.get(f.severity, 3))
    if findings:
        out.print()
        rows = []
        for f in findings[: max(top, 8)]:
            sev = f"[{_SEV_STYLE.get(f.severity,'')}]{f.severity.upper()}[/]" if out._rich else f.severity.upper()
            rows.append((sev, f.kind, f.title))
        out.table(["sev", "kind", "finding"], rows, title="findings")
        # detail lines
        out.print()
        for f in findings[: max(top, 8)]:
            out.print(f"[bold]• {f.title}[/]" if out._rich else f"• {f.title}")
            out.hint(f.detail)
            if f.suggest:
                out.hint(f"→ {f.suggest}")

    if report.credentials:
        out.print()
        out.table(["protocol", "credential", "where"],
                  [(p, c, w) for p, c, w in report.credentials[:top]],
                  title="cleartext credentials")

    if report.decoded:
        out.print()
        out.table(["location", "recipe", "decoded"],
                  [(d.where, d.recipe, ("★ " if d.is_flag else "") + d.preview)
                   for d in report.decoded[:top]],
                  title="auto-decoded blobs")

    if report.flags:
        out.print()
        out.success("FLAG(S) recovered:")
        for f in report.flags:
            out.raw(f)

    out.print()
    out.panel("\n".join(f"{i+1}. {r}" for i, r in enumerate(report.requirements)),
              title="requirements to reach the scenario flag", style="bold #d97706")


def _render_endpoints(report: PcapReport, out, top: int) -> int:
    rows = []
    for c in report.conversations[:max(top, 20)]:
        tag = "EXT" if c.external else "int"
        rows.append((tag, c.a, c.b, c.proto, f"{c.bytes:,}", c.packets,
                     ",".join(str(p) for p in sorted(c.ports)[:5])))
    out.table(["scope", "host A", "host B", "proto", "bytes", "pkts", "dst ports"],
              rows, title="conversations (by bytes)")
    return 0


def _render_creds(report: PcapReport, out) -> int:
    if not report.credentials:
        out.warn("no cleartext credentials found")
        return 1
    out.table(["protocol", "credential", "where"],
              [(p, c, w) for p, c, w in report.credentials], title="cleartext credentials")
    return 0


def _render_dns(report: PcapReport, out) -> int:
    rows = [(n, report.dns_names[n], report.dns_map.get(n, ""))
            for n in sorted(report.dns_names, key=lambda k: -report.dns_names[k])]
    out.table(["query", "count", "resolved"], rows, title="DNS queries")
    return 0


def _carve(path: str, outdir: str, out) -> None:
    """Best-effort extraction of cleartext HTTP response bodies via scapy."""
    import os
    require("scapy", "pcap carving")
    from scapy.all import PcapReader, TCP, Raw  # type: ignore
    os.makedirs(outdir, exist_ok=True)
    streams: Dict[Tuple, bytearray] = defaultdict(bytearray)
    for pkt in PcapReader(path):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            t = pkt[TCP]
            streams[(pkt.payload.src if hasattr(pkt.payload, "src") else "?",
                     int(t.sport), int(t.dport))] += bytes(pkt[Raw].load)
    n = 0
    for (src, sport, dport), data in streams.items():
        blob = bytes(data)
        idx = blob.find(b"\r\n\r\n")
        if b"HTTP/" in blob[:16] and idx != -1:
            body = blob[idx + 4:]
            if body:
                fn = os.path.join(outdir, f"http_{src}_{sport}_{n}.bin")
                with open(fn, "wb") as fh:
                    fh.write(body)
                n += 1
    out.success(f"carved {n} HTTP object(s) into {outdir}")
    out.hint(f"now: aesop magic -f {outdir}/<file>   or   aesop identify -f <file>")

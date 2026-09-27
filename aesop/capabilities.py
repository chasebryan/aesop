"""
aesop.capabilities — what optional power-ups are installed.

AESOP works with only the standard library plus ``rich``.  Several attacks get
faster or unlock extra modes when optional libraries are present.  This module
probes for them so ``aesop version`` can report honestly and modules can degrade
gracefully.
"""
from __future__ import annotations

import importlib
from typing import List, Tuple

# name -> (import module, human note when present)
_OPTIONAL = [
    ("sympy", "fast factoring, primality, discrete-log for RSA/DLP attacks"),
    ("gmpy2", "big-integer speedups for factoring & lattice math"),
    ("Crypto", "PyCryptodome: real cipher primitives for oracle attacks"),
    ("cryptography", "X.509 / key parsing"),
    ("fpylll", "LLL lattice reduction (Coppersmith, Boneh-Durfee)"),
    ("z3", "SMT solving for constraint-based recovery"),
    ("requests", "online factordb / hash lookups"),
    ("scapy", "packet-capture (pcap) forensics & traffic analysis"),
]


def has(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except Exception:
        return False


def capability_report() -> List[Tuple[str, bool, str]]:
    out: List[Tuple[str, bool, str]] = []
    for mod, note in _OPTIONAL:
        out.append((mod, has(mod), note))
    return out


def require(module: str, feature: str) -> None:
    """Raise a friendly error if an optional dependency is missing."""
    if not has(module):
        raise RuntimeError(
            f"{feature} needs the optional package '{module}'. "
            f"Install it with:  pip install {module}"
        )

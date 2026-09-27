"""
AESOP — Analytic Encryption-Solving Oracle Platform.

An all-in-one cryptanalysis workbench for CTF, security research and teaching.
Named for Aesop the fabulist: every ciphertext, like every fable, hides a truth
beneath its surface — and the clever fox always finds it.

Public entry point is :func:`aesop.cli.main`.  The programmatic API lives in the
technique modules (``aesop.classical.*``, ``aesop.modern.*``,
``aesop.encoding.*``) and the shared core (``aesop.core.*``).
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "AESOP contributors"
__all__ = ["__version__"]

"""
Integration tests for the AESOP framework as a whole.

These do not test individual crypto algorithms (each module has its own
``test_<module>.py`` for that) — they verify the *tool* holds together: every
module imports, every command is well-formed, manual pages exist, and the core
scoring/detection/IO utilities behave.
"""
from __future__ import annotations

import importlib
import subprocess
import sys

import pytest

from aesop import cli
from aesop.registry import REGISTRY, GROUPS
from aesop.manual import load_manual


def test_all_declared_modules_import():
    """Every module the CLI advertises must import without error."""
    cli._load_modules()
    if cli._IMPORT_ERRORS:
        pytest.fail("module import errors:\n" + "\n".join(f"  {m}: {e}" for m, e in cli._IMPORT_ERRORS))


def test_registry_populated():
    cli._load_modules()
    assert len(REGISTRY) >= 20, f"expected many commands, got {len(REGISTRY)}"


def test_every_command_is_wellformed():
    cli._load_modules()
    for name, cmd in REGISTRY.items():
        assert cmd.group in GROUPS, f"{name}: bad group {cmd.group}"
        assert cmd.summary, f"{name}: missing summary"
        assert callable(cmd.handler), f"{name}: handler not callable"


def test_every_command_has_a_manual_page():
    cli._load_modules()
    pages = load_manual()
    missing = []
    for name, cmd in REGISTRY.items():
        if cmd.manual and cmd.manual not in pages:
            missing.append(f"{name} -> manual '{cmd.manual}'")
    assert not missing, "commands referencing absent manual pages:\n" + "\n".join(missing)


def test_no_duplicate_commands_or_aliases():
    cli._load_modules()
    seen = {}
    for name, cmd in REGISTRY.items():
        for tok in [name] + list(cmd.aliases):
            assert tok not in seen, f"duplicate name/alias {tok!r} ({name} vs {seen[tok]})"
            seen[tok] = name


def test_parser_builds():
    cli._load_modules()
    parser = cli.build_parser()
    assert parser is not None


def test_manual_pages_have_summaries():
    pages = load_manual()
    assert pages, "no manual pages found"
    for slug, page in pages.items():
        assert page.summary, f"manual page {slug} missing '> summary' line"


# -- core utilities ---------------------------------------------------------- #
def test_core_scoring_ranks_english_highest():
    from aesop.core.score import score_text
    good = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    bad = "XQZJKVBWPMQXZJKVBWPMXQZJKVBWPMQXZJK"
    assert score_text(good) > score_text(bad)


def test_core_number_theory():
    from aesop.core.util import modinv, egcd, crt, iroot, continued_fraction, convergents
    assert modinv(3, 26) == 9
    g, x, y = egcd(240, 46)
    assert 240 * x + 46 * y == g
    val, mod = crt([2, 3, 2], [3, 5, 7])
    assert val % 3 == 2 and val % 5 == 3 and val % 7 == 2
    r, exact = iroot(27, 3)
    assert r == 3 and exact
    assert list(convergents(continued_fraction(7, 3)))[-1] == (7, 3)


def test_smart_io_sniffing():
    from aesop.core.io import sniff_encoding
    assert sniff_encoding("Nggnpx ng qnja") == "raw"
    assert sniff_encoding("48656c6c6f") == "hex"
    assert sniff_encoding("SGVsbG8=") == "base64"


def test_detect_identifies_base64():
    from aesop.core.detect import identify
    guesses = identify(b"SGVsbG8gV29ybGQh")
    labels = [g.label for g in guesses]
    assert any("base64" in l for l in labels)


# -- CLI as a subprocess (end to end) ---------------------------------------- #
def _run(*args, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "aesop", *args],
        input=stdin, capture_output=True, text=True, timeout=60,
    )


def test_cli_version_runs():
    r = _run("version")
    assert r.returncode == 0
    assert "AESOP" in r.stdout


def test_cli_list_runs():
    r = _run("list")
    assert r.returncode == 0


def test_cli_caesar_end_to_end():
    r = _run("caesar", "Wkh txlfn eurzq ira")
    assert r.returncode == 0
    assert "quick brown fox" in r.stdout.lower()


def test_cli_manual_renders():
    r = _run("manual", "caesar")
    assert r.returncode == 0
    assert "Caesar" in r.stdout

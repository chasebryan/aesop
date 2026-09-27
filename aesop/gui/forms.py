"""
aesop.gui.forms — turn a registry :class:`~aesop.registry.Command` into a form.

The CLI builds an ``argparse`` parser from each command's ``Arg`` specs; the
workbench builds a *form* from the very same specs.  Values the user enters are
converted back into an ``argv`` list and parsed by the real parser, so a run
from the GUI is — by construction — the same as the command line it displays.

Toolkit-free: nothing here imports a GUI library.
"""
from __future__ import annotations

import argparse
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..registry import Command

# Field kinds the front end knows how to draw.
INPUT = "input"        # the main data box (the io_args positional)
TEXT = "text"
INT = "int"
FLOAT = "float"
CHOICE = "choice"
FLAG = "flag"
PATH = "path"
DIR = "dir"
LIST = "list"          # repeatable option / variadic positional

_PATH_METAVARS = {"PATH", "FILE", "CAPTURE"}
_DIR_METAVARS = {"DIR"}


class FormError(ValueError):
    """The values (or an example line) do not form a valid invocation."""


@dataclass
class Field:
    dest: str
    flags: List[str]                 # [] for a positional
    kind: str
    help: str = ""
    default: Any = None
    choices: List[str] = field(default_factory=list)
    metavar: str = ""
    required: bool = False

    @property
    def positional(self) -> bool:
        return not self.flags

    @property
    def flag(self) -> str:
        """The spelling used on command lines — the long form when there is one."""
        return next((f for f in self.flags if f.startswith("--")), self.flags[0])

    @property
    def label(self) -> str:
        if self.positional:
            return self.metavar or self.dest
        return ", ".join(self.flags)


def _dest(names: List[str], kwargs: Dict[str, Any]) -> str:
    if "dest" in kwargs:
        return kwargs["dest"]
    if not names[0].startswith("-"):
        return names[0]
    longs = [n for n in names if n.startswith("--")]
    return (longs[0] if longs else names[0]).lstrip("-").replace("-", "_")


def _kind(names: List[str], kw: Dict[str, Any]) -> str:
    positional = not names[0].startswith("-")
    metavar = str(kw.get("metavar") or "")
    if kw.get("action") == "store_true":
        return FLAG
    if kw.get("action") == "append" or kw.get("nargs") in ("*", "+"):
        return LIST
    if kw.get("choices"):
        return CHOICE
    if metavar in _DIR_METAVARS:
        return DIR
    if metavar in _PATH_METAVARS:
        return PATH
    if positional and kw.get("nargs") == "?":
        return INPUT
    if kw.get("type") is int:
        return INT
    if kw.get("type") is float:
        return FLOAT
    return TEXT


def fields_for(cmd: Command) -> List[Field]:
    """The form fields for ``cmd``, in declaration order."""
    out: List[Field] = []
    for a in cmd.args:
        names = a.name.split()
        kw = a.kwargs
        positional = not names[0].startswith("-")
        out.append(Field(
            dest=_dest(names, kw),
            flags=[] if positional else names,
            kind=_kind(names, kw),
            help=a.help,
            default=kw.get("default"),
            choices=[str(c) for c in kw.get("choices") or []],
            metavar=str(kw.get("metavar") or ""),
            required=(positional and kw.get("nargs") not in ("?", "*")) or bool(kw.get("required")),
        ))
    return out


# --------------------------------------------------------------------------- #
# values -> argv
# --------------------------------------------------------------------------- #
def _is_default(f: Field, value: Any) -> bool:
    return f.default is not None and str(value) == str(f.default)


def _option(f: Field, value: str) -> List[str]:
    """Spell ``flag value`` so a value starting with '-' is never read as a flag."""
    if not value.startswith("-"):
        return [f.flag, value]
    if f.flag.startswith("--"):
        return [f"{f.flag}={value}"]
    return [f.flag + value]


def split_list(value: Any) -> List[str]:
    """A LIST field's entries: one per line, or comma/space separated."""
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v).strip()]
    return [v for v in str(value or "").replace(",", " ").split() if v]


def build_argv(cmd: Command, values: Dict[str, Any]) -> List[str]:
    """The argument list (command name first) equivalent to the form ``values``.

    Empty fields and fields left at their default are omitted, so the result
    reads like something a person would type.
    """
    argv: List[str] = [cmd.name]
    positionals: List[str] = []
    for f in fields_for(cmd):
        value = values.get(f.dest)
        if f.kind == FLAG:
            if value:
                argv.append(f.flag)
            continue
        if f.kind == LIST:
            items = split_list(value)
            if f.positional:
                positionals.extend(items)
            else:
                for item in items:
                    argv.extend(_option(f, item))
            continue
        if value is None or str(value) == "":
            continue
        if f.positional:
            positionals.append(str(value))
        elif not _is_default(f, value):
            argv.extend(_option(f, str(value)))
    if any(p.startswith("-") for p in positionals):
        argv.append("--")
    return argv + positionals


def missing_required(cmd: Command, values: Dict[str, Any]) -> List[Field]:
    """Required fields the user has not filled in."""
    return [f for f in fields_for(cmd)
            if f.required and not str(values.get(f.dest) or "").strip()]


def command_line(argv: List[str], max_arg: int = 0) -> str:
    """``argv`` as a shell line.  ``max_arg`` elides long arguments for display."""
    parts = []
    for a in argv:
        if max_arg and len(a) > max_arg:
            a = a[:max_arg - 1].replace("\n", " ") + "…"
        parts.append(shlex.quote(a))
    return "aesop " + " ".join(parts)


# --------------------------------------------------------------------------- #
# argv -> values  (loading an example or a history entry into the form)
# --------------------------------------------------------------------------- #
class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # raise instead of printing usage + exiting
        raise FormError(message)

    def exit(self, status: int = 0, message: Optional[str] = None):
        raise FormError((message or "").strip() or "help requested")


def _raw_parser(cmd: Command) -> argparse.ArgumentParser:
    """A parser for ``cmd`` that keeps values as the strings the user typed.

    ``type`` and ``choices`` are dropped on purpose: the form shows text, and a
    value like ``0x10001`` should round-trip as written rather than as 65537.
    """
    p = _Parser(prog=cmd.name, add_help=False)
    for a in cmd.args:
        kw = {k: v for k, v in a.kwargs.items() if k not in ("type", "choices", "default")}
        p.add_argument(*a.name.split(), **kw)
    return p


def values_from_argv(cmd: Command, args: List[str]) -> Dict[str, Any]:
    """Form values for ``args`` (the arguments *after* the command name)."""
    ns = _raw_parser(cmd).parse_args(args)
    values: Dict[str, Any] = {}
    for f in fields_for(cmd):
        v = getattr(ns, f.dest, None)
        if f.kind == FLAG:
            values[f.dest] = bool(v)
        elif f.kind == LIST:
            values[f.dest] = [str(x) for x in (v or [])]
        elif v is not None:
            values[f.dest] = str(v)
    return values


_SHELL_PUNCT = set("();<>|&")
_MORSE = re.compile(r"^[.\-/ ]+$")


def _elided(token: str) -> bool:
    """True for arguments like ``0x...`` that stand in for the reader's own data."""
    return token.endswith(("...", "…")) and not _MORSE.match(token)


def parse_example(line: str) -> Optional[Tuple[str, List[str], Optional[str]]]:
    """Understand a documented example line.

    Returns ``(command, args, piped_input)`` or ``None`` when the line is not a
    plain AESOP invocation.  Two shapes are understood::

        aesop caesar --all 'Uryyb Jbeyq'     # trailing comments are fine
        echo 'Fdhvdu flskhu' | aesop caesar  # piped_input = 'Fdhvdu flskhu'
    """
    line = line.strip()
    if line.startswith("$ "):
        line = line[2:]
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = "#"
        toks = list(lex)
    except ValueError:
        return None
    piped: Optional[str] = None
    if len(toks) >= 4 and toks[0] == "echo" and "|" in toks:
        bar = toks.index("|")
        words = [t for t in toks[1:bar] if t not in ("-n", "-e")]
        piped = " ".join(words)
        toks = toks[bar + 1:]
    if any(t and set(t) <= _SHELL_PUNCT for t in toks):
        return None                     # pipelines, redirects, substitutions
    if len(toks) >= 3 and toks[1] == "-m" and toks[2] == "aesop":
        toks = toks[2:]                 # python -m aesop …
    if len(toks) < 2 or toks[0] != "aesop":
        return None
    if any(_elided(t) for t in toks[2:]):
        return None                     # a placeholder, not real data
    return toks[1], toks[2:], piped

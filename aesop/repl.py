"""
aesop.repl — an interactive shell.

``aesop repl`` drops you into a prompt where you can run any AESOP command
without the ``aesop`` prefix, keeping a scratch "workspace" of the last result
so you can chain steps (decode, then analyse, then solve).  Uses
``prompt_toolkit`` for history/completion when available, else a plain loop.
"""
from __future__ import annotations

import shlex
from typing import List, Optional

from .registry import REGISTRY, resolve, GROUPS, commands_by_group
from .ui import Output, FOX


def _completer():
    try:
        from prompt_toolkit.completion import WordCompleter
    except Exception:
        return None
    words = ["manual", "list", "version", "help", "quit", "exit"]
    words += list(REGISTRY.keys())
    return WordCompleter(words, ignore_case=True, sentence=True)


def run_repl(out: Output) -> int:
    out.panel(
        "Interactive AESOP.  Type a command (without the `aesop` prefix), "
        "`list` for the catalogue, `manual <topic>` for theory, `quit` to leave.",
        title="the fox's den", style=FOX,
    )
    session = None
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import InMemoryHistory
        session = PromptSession(history=InMemoryHistory(), completer=_completer())
    except Exception:
        session = None

    from .cli import _handle_manual, _handle_list, _handle_version, build_parser
    import argparse

    while True:
        try:
            if session is not None:
                line = session.prompt("aesop » ")
            else:
                line = input("aesop » ")
        except (EOFError, KeyboardInterrupt):
            out.print()
            return 0
        line = line.strip()
        if not line:
            continue
        if line in ("quit", "exit", "q"):
            return 0
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            out.error(str(exc))
            continue

        name, rest = parts[0], parts[1:]
        if name in ("help", "?"):
            _run_meta("list", out)
            continue
        if name in ("list", "ls", "commands"):
            _run_meta("list", out, rest)
            continue
        if name in ("manual", "man"):
            _run_meta("manual", out, rest)
            continue
        if name in ("version",):
            _run_meta("version", out)
            continue

        cmd = resolve(name)
        if not cmd:
            out.warn(f"unknown command {name!r} — type `list`")
            continue
        # Build a tiny parser just for this command's args.
        parser = argparse.ArgumentParser(prog=cmd.name, add_help=True)
        for a in cmd.args:
            parser.add_argument(*a.name.split(), help=a.help, **a.kwargs)
        try:
            ns = parser.parse_args(rest)
        except SystemExit:
            continue
        try:
            cmd.handler(ns, out)
        except Exception as exc:
            out.error(f"{type(exc).__name__}: {exc}")
    return 0


def _run_meta(which: str, out: Output, rest: Optional[List[str]] = None) -> None:
    import argparse
    from .cli import _handle_manual, _handle_list, _handle_version
    rest = rest or []
    ns = argparse.Namespace()
    if which == "manual":
        ns.topic = rest[0] if rest else None
        ns.search = None
        ns.raw = False
        _handle_manual(ns, out)
    elif which == "list":
        ns.group = rest[0] if rest else None
        _handle_list(ns, out)
    elif which == "version":
        ns.debug = False
        _handle_version(ns, out)

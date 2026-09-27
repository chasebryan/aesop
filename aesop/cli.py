"""
aesop.cli — the command-line entry point.

Builds an ``argparse`` parser from the plug-in :mod:`aesop.registry`, wires the
built-in reference commands (``manual``, ``list``, ``version``, ``repl``,
``gui``), and
dispatches to handlers.  Import side effects in the technique modules populate
the registry, so adding a capability never means editing this file.
"""
from __future__ import annotations

import argparse
import importlib
import sys
import textwrap
from typing import List, Tuple

from . import __version__
from .registry import REGISTRY, GROUPS, Command, resolve, commands_by_group
from .ui import Output, FOX

# Technique modules whose import registers commands.  Missing modules are
# tolerated so a partial checkout still runs (reported under --debug).
_MODULES = [
    "aesop.analysis.detect_cmd",
    "aesop.analysis.freq_cmd",
    "aesop.analysis.entropy_cmd",
    "aesop.classical.caesar",
    "aesop.classical.vigenere",
    "aesop.classical.substitution",
    "aesop.classical.affine",
    "aesop.classical.transposition",
    "aesop.classical.xor",
    "aesop.classical.playfair",
    "aesop.classical.hill",
    "aesop.classical.misc",
    "aesop.modern.rsa",
    "aesop.modern.blockcipher",
    "aesop.modern.hashes",
    "aesop.modern.prng",
    "aesop.encoding.bases",
    "aesop.encoding.magic",
    "aesop.analysis.autosolve",
    "aesop.network.pcap",
]

_IMPORT_ERRORS: List[Tuple[str, str]] = []


def _load_modules() -> None:
    for mod in _MODULES:
        try:
            importlib.import_module(mod)
        except Exception as exc:  # keep the CLI alive on a broken/absent module
            _IMPORT_ERRORS.append((mod, f"{type(exc).__name__}: {exc}"))


BANNER = r"""
    /\_/\     AESOP
   ( o.o )    Analytic Encryption-Solving Oracle Platform
    > ^ <     the cryptanalyst's book of fables
"""


def _common_parent() -> argparse.ArgumentParser:
    """Flags accepted both before and after the subcommand.

    Defaults are SUPPRESSed so parsing a subcommand never clobbers a value the
    top-level parser already set (the classic argparse subparser pitfall).
    """
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                        help="disable coloured output")
    common.add_argument("--color", action="store_true", default=argparse.SUPPRESS,
                        help="force coloured output")
    common.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS,
                        help="suppress non-essential output")
    common.add_argument("--debug", action="store_true", default=argparse.SUPPRESS,
                        help="show tracebacks and load errors")
    return common


def _add_command(subparsers: argparse._SubParsersAction, cmd: Command,
                 common: argparse.ArgumentParser) -> None:
    epilog = ""
    if cmd.examples:
        epilog = "examples:\n" + "\n".join(f"  {e}" for e in cmd.examples)
    if cmd.manual:
        epilog += f"\n\nmanual: aesop manual {cmd.manual}"
    p = subparsers.add_parser(
        cmd.name,
        help=cmd.summary,
        description=textwrap.dedent(cmd.description).strip() or cmd.summary,
        aliases=cmd.aliases,
        epilog=epilog or None,
        parents=[common],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    for a in cmd.args:
        names = a.name.split()
        p.add_argument(*names, help=a.help, **a.kwargs)
    p.set_defaults(_cmd=cmd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aesop",
        description="AESOP — an all-in-one cryptanalysis workbench for CTF, "
                    "research and teaching. Every command has a manual: "
                    "`aesop manual <topic>`.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run `aesop list` for the full catalogue, or `aesop manual` for the field guide.",
    )
    parser.add_argument("--version", action="version", version=f"aesop {__version__}")
    common = _common_parent()
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--color", action="store_true", help="force coloured output")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress non-essential output")
    parser.add_argument("--debug", action="store_true", help="show tracebacks and load errors")

    sub = parser.add_subparsers(dest="_command", metavar="<command>")

    # Built-in meta commands first.
    _build_meta(sub, common)

    # Registered technique commands, grouped.
    for cmd in sorted(REGISTRY.values(), key=lambda c: (list(GROUPS).index(c.group), c.name)):
        _add_command(sub, cmd, common)

    return parser


def _build_meta(sub: argparse._SubParsersAction, common: argparse.ArgumentParser) -> None:
    m = sub.add_parser("manual", help="read the built-in field guide",
                       parents=[common], aliases=["man", "help-topic"])
    m.add_argument("topic", nargs="?", help="topic slug (omit to list all)")
    m.add_argument("--search", metavar="TERM", help="search manual text")
    m.add_argument("--raw", action="store_true", help="print raw markdown")
    m.set_defaults(_meta="manual")

    lst = sub.add_parser("list", help="list every command by category",
                         parents=[common], aliases=["ls", "commands"])
    lst.add_argument("--group", help="filter to one category")
    lst.set_defaults(_meta="list")

    ver = sub.add_parser("version", help="show version and capabilities", parents=[common])
    ver.set_defaults(_meta="version")

    rp = sub.add_parser("repl", help="start an interactive session",
                        parents=[common], aliases=["shell", "i"])
    rp.set_defaults(_meta="repl")

    gui = sub.add_parser("gui", help="open the graphical workbench",
                         parents=[common], aliases=["workbench"])
    gui.add_argument("start", nargs="?", metavar="command",
                     help="command to open with (default: the last one used)")
    gui.add_argument("--theme", choices=["dark", "light"],
                     help="colour theme (default: the last one used)")
    gui.set_defaults(_meta="gui")


# --------------------------------------------------------------------------- #
# Meta-command handlers
# --------------------------------------------------------------------------- #
def _handle_manual(args, out: Output) -> int:
    from .manual import load_manual, get_page, search_manual

    if args.search:
        hits = search_manual(args.search)
        if not hits:
            out.warn(f"no manual pages mention {args.search!r}")
            return 1
        out.table(["topic", "title"], [(p.slug, p.summary or p.title) for p in hits],
                  title=f"pages mentioning “{args.search}”")
        return 0

    if not args.topic:
        pages = load_manual()
        if not pages:
            out.warn("no manual pages found")
            return 1
        rows = [(slug, p.summary or p.title) for slug, p in sorted(pages.items())]
        out.table(["topic", "summary"], rows, title="AESOP field guide — `aesop manual <topic>`")
        return 0

    page = get_page(args.topic)
    if not page:
        out.error(f"no manual page for {args.topic!r}. Try `aesop manual` to list topics.")
        return 1
    if args.raw:
        out.raw(page.body())
    else:
        out.markdown(page.body())
    return 0


def _handle_list(args, out: Output) -> int:
    groups = commands_by_group()
    out.print(f"[{FOX}]AESOP command catalogue[/]" if out._rich else "AESOP command catalogue")
    for gkey, glabel in GROUPS.items():
        cmds = groups.get(gkey, [])
        if args.group and args.group not in (gkey, glabel):
            continue
        if not cmds:
            continue
        out.print()
        out.table(["command", "what it does"],
                  [(c.name + (f"  ({', '.join(c.aliases)})" if c.aliases else ""), c.summary)
                   for c in cmds],
                  title=glabel)
    out.print()
    out.hint("Detailed help:  aesop <command> -h        Theory:  aesop manual <topic>")
    return 0


def _handle_version(args, out: Output) -> int:
    from .capabilities import capability_report
    out.panel(BANNER.strip("\n"), title="", style=FOX)
    out.keyval([("version", __version__),
                ("commands", len(REGISTRY)),
                ("manual pages", len(__import__("aesop.manual", fromlist=["load_manual"]).load_manual()))],
               title="AESOP")
    out.print()
    rows = [(name, "yes" if ok else "no", note) for name, ok, note in capability_report()]
    out.table(["optional feature", "available", "detail"], rows, title="capabilities")
    if _IMPORT_ERRORS and args.debug:
        out.print()
        out.table(["module", "error"], _IMPORT_ERRORS, title="module load errors")
    return 0


def _handle_repl(args, out: Output) -> int:
    from .repl import run_repl
    return run_repl(out)


def _handle_gui(args, out: Output) -> int:
    if args.start and not resolve(args.start):
        out.error(f"unknown command {args.start!r} — see `aesop list`")
        return 2
    from .gui import run_gui
    return run_gui(command=args.start, theme=args.theme)


def main(argv: List[str] | None = None) -> int:
    # Restore default SIGPIPE handling so `aesop … | head` exits quietly instead
    # of Python printing a BrokenPipeError at interpreter shutdown.
    try:
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (AttributeError, ValueError, OSError):  # not on Windows / non-main thread
        pass
    _load_modules()
    parser = build_parser()
    args = parser.parse_args(argv)

    out = Output(color=(True if getattr(args, "color", False) else
                        False if getattr(args, "no_color", False) else None),
                 quiet=getattr(args, "quiet", False))

    meta = getattr(args, "_meta", None)
    if meta == "manual":
        return _handle_manual(args, out)
    if meta == "list":
        return _handle_list(args, out)
    if meta == "version":
        return _handle_version(args, out)
    if meta == "repl":
        return _handle_repl(args, out)
    if meta == "gui":
        return _handle_gui(args, out)

    cmd: Command = getattr(args, "_cmd", None)
    if cmd is None:
        parser.print_help()
        if _IMPORT_ERRORS and getattr(args, "debug", False):
            out.print()
            out.table(["module", "error"], _IMPORT_ERRORS, title="module load errors")
        return 0

    try:
        return cmd.handler(args, out) or 0
    except KeyboardInterrupt:
        out.error("interrupted")
        return 130
    except BrokenPipeError:  # piping into head, etc.
        return 0
    except Exception as exc:  # pragma: no cover
        if getattr(args, "debug", False):
            raise
        out.error(f"{type(exc).__name__}: {exc}")
        out.hint("re-run with --debug for a traceback")
        return 1


if __name__ == "__main__":
    sys.exit(main())

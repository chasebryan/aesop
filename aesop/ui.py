"""
aesop.ui — consistent, pretty terminal output.

A thin wrapper over ``rich`` (with a plain-text fallback if rich is missing) so
every command in the fable speaks with one voice: the fox's green for success,
amber for warnings, a muted grey for hints, and clean tables/panels for
results.  Command handlers receive an :class:`Output` instance and never touch
``print`` directly.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Iterable, List, Optional, Sequence, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markdown import Markdown
    from rich.text import Text
    from rich.syntax import Syntax
    _HAVE_RICH = True
except Exception:  # pragma: no cover
    _HAVE_RICH = False

# The fable's palette.
FOX = "bold #d97706"       # amber-orange — the fox, brand accent
GOOD = "bold green"
WARN = "yellow"
BAD = "bold red"
DIM = "dim"
KEY = "bold cyan"


class Output:
    """Facade for all terminal output."""

    def __init__(self, color: Optional[bool] = None, quiet: bool = False):
        self.quiet = quiet
        force = None
        if color is False or os.environ.get("NO_COLOR"):
            force = False
        elif color is True:
            force = True
        self._rich = _HAVE_RICH and (force is not False)
        if self._rich:
            self.console = Console(force_terminal=force, highlight=False, soft_wrap=False)
            self.err_console = Console(stderr=True, force_terminal=force, highlight=False)
        else:
            self.console = None
            self.err_console = None

    # -- primitive lines ---------------------------------------------------- #
    def print(self, *args: Any, **kwargs: Any) -> None:
        if self.quiet:
            return
        if self._rich:
            self.console.print(*args, **kwargs)
        else:
            print(*[_strip(a) for a in args])

    def raw(self, s: str) -> None:
        """Print without any markup interpretation (safe for arbitrary data)."""
        if self.quiet:
            return
        sys.stdout.write(s)
        if not s.endswith("\n"):
            sys.stdout.write("\n")

    def success(self, msg: str) -> None:
        self._tagged("✓", GOOD, msg)

    def info(self, msg: str) -> None:
        self._tagged("•", KEY, msg)

    def warn(self, msg: str) -> None:
        self._tagged("!", WARN, msg)

    def error(self, msg: str) -> None:
        if self._rich:
            self.err_console.print(f"[{BAD}]✗ {msg}[/]")
        else:
            print(f"error: {_strip(msg)}", file=sys.stderr)

    def hint(self, msg: str) -> None:
        if self.quiet:
            return
        if self._rich:
            self.console.print(f"[{DIM}]  {msg}[/]")
        else:
            print(f"  {_strip(msg)}")

    def rule(self, title: str = "") -> None:
        if self.quiet:
            return
        if self._rich:
            self.console.rule(f"[{FOX}]{title}[/]" if title else "")
        else:
            print("-" * 60 + (f" {title}" if title else ""))

    def _tagged(self, glyph: str, style: str, msg: str) -> None:
        if self.quiet:
            return
        if self._rich:
            self.console.print(f"[{style}]{glyph}[/] {msg}")
        else:
            print(f"{glyph} {_strip(msg)}")

    # -- structured widgets ------------------------------------------------- #
    def panel(self, body: str, title: str = "", style: str = FOX) -> None:
        if self.quiet:
            return
        if self._rich:
            self.console.print(Panel(body, title=f"[{style}]{title}[/]" if title else None,
                                     border_style=style, expand=False))
        else:
            if title:
                print(f"== {_strip(title)} ==")
            print(_strip(body))

    def table(self, columns: Sequence[str], rows: Iterable[Sequence[Any]],
              title: str = "") -> None:
        rows = list(rows)
        if self._rich:
            t = Table(title=f"[{FOX}]{title}[/]" if title else None,
                      show_header=True, header_style=KEY, expand=False)
            for c in columns:
                t.add_column(str(c))
            for r in rows:
                t.add_row(*[_cellify(x) for x in r])
            self.console.print(t)
        else:
            if title:
                print(f"== {_strip(title)} ==")
            widths = [len(str(c)) for c in columns]
            for r in rows:
                for i, x in enumerate(r):
                    widths[i] = max(widths[i], len(_strip(_cellify(x))))
            fmt = "  ".join("{:<%d}" % w for w in widths)
            print(fmt.format(*[str(c) for c in columns]))
            print(fmt.format(*["-" * w for w in widths]))
            for r in rows:
                print(fmt.format(*[_strip(_cellify(x)) for x in r]))

    def keyval(self, pairs: Sequence[Tuple[str, Any]], title: str = "") -> None:
        """A two-column key/value panel — the default result renderer."""
        if title:
            self.print(f"[{FOX}]{title}[/]" if self._rich else f"== {title} ==")
        width = max((len(str(k)) for k, _ in pairs), default=0)
        for k, v in pairs:
            if self._rich:
                self.console.print(f"  [{KEY}]{str(k):<{width}}[/]  {_cellify(v)}")
            else:
                print(f"  {str(k):<{width}}  {_strip(_cellify(v))}")

    def markdown(self, md: str) -> None:
        if self.quiet:
            return
        if self._rich:
            self.console.print(Markdown(md))
        else:
            print(_strip(md))

    def code(self, code: str, lang: str = "text") -> None:
        if self._rich:
            self.console.print(Syntax(code, lang, theme="ansi_dark", word_wrap=True))
        else:
            print(_strip(code))


def _cellify(x: Any) -> str:
    if isinstance(x, (bytes, bytearray)):
        try:
            return x.decode("latin-1")
        except Exception:
            return x.hex()
    return str(x)


def _strip(s: Any) -> str:
    """Remove rich markup for the plain-text fallback."""
    import re
    return re.sub(r"\[/?[^\]]*\]", "", str(s))

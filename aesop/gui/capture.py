"""
aesop.gui.capture — an :class:`~aesop.ui.Output` that records instead of printing.

Command handlers only ever talk to the ``out`` facade, so a front end that is
not a terminal just needs its own facade.  :class:`CaptureOutput` turns every
call into a small JSON-friendly *event* dict and hands it to a callback; the
workbench renders those events natively (real tables, styled text, panels)
instead of scraping terminal output.

Event kinds::

    {"kind": "line",   "style": "plain|success|info|warn|error|hint", "spans": [[text, style], …]}
    {"kind": "blank"}
    {"kind": "raw",    "text": str}                      # a command's primary result
    {"kind": "rule",   "title": str}
    {"kind": "panel",  "title": str, "spans": [[text, style], …]}
    {"kind": "table",  "title": str, "columns": [str], "rows": [[[text, style], …], …]}
    {"kind": "keyval", "title": str, "pairs": [[key, value], …]}
    {"kind": "markdown", "text": str}
    {"kind": "code",   "text": str, "lang": str}

This module has no GUI-toolkit imports, so it is usable (and tested) headless.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, List, Sequence, Tuple

from ..ui import Output, _cellify

Span = Tuple[str, str]
Event = Dict[str, Any]

# --------------------------------------------------------------------------- #
# Console markup
# --------------------------------------------------------------------------- #
_ATTRS = {"bold", "dim", "italic", "underline", "strike", "reverse", "blink"}
_COLOURS = {"black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
            "grey", "gray", "default"}
_HEX_COLOUR = re.compile(r"^#[0-9a-fA-F]{6}$")
_TAG = re.compile(r"(\\*)\[(/?)([^\[\]]*)\]")


def _is_colour(tok: str) -> bool:
    if tok.startswith("bright_"):
        tok = tok[len("bright_"):]
    return tok in _COLOURS or bool(_HEX_COLOUR.match(tok))


def is_style(tag: str) -> bool:
    """True if ``tag`` is a style AESOP's handlers could plausibly have meant.

    Deliberately strict: handlers interpolate untrusted data (candidate
    plaintexts, keys) into their messages, and bracketed data such as ``[abc]``
    must survive as text rather than vanish as an unknown "style".
    """
    toks = tag.split()
    if not toks:
        return False
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok in ("on", "not"):
            i += 1
            if i >= len(toks):
                return False
            ok = _is_colour(toks[i]) if tok == "on" else toks[i] in _ATTRS
            if not ok:
                return False
        elif not (tok in _ATTRS or _is_colour(tok)):
            return False
        i += 1
    return True


def parse_markup(text: Any) -> List[Span]:
    """Split console markup into ``(text, style)`` spans.

    Only tags that pass :func:`is_style` (and their closers) are consumed;
    everything else is literal.  ``\\[`` escapes a bracket.
    """
    text = str(text)
    spans: List[Span] = []
    stack: List[str] = []
    pos = 0

    def push(chunk: str) -> None:
        if not chunk:
            return
        style = " ".join(stack)
        if spans and spans[-1][1] == style:
            spans[-1] = (spans[-1][0] + chunk, style)
        else:
            spans.append((chunk, style))

    for m in _TAG.finditer(text):
        backslashes, closing, tag = m.group(1), m.group(2), m.group(3).strip()
        literal = text[pos:m.start()]
        pos = m.end()
        if len(backslashes) % 2:                      # escaped: \[tag]
            push(literal + backslashes[:-1] + m.group(0)[len(backslashes):])
            continue
        if closing and stack and (not tag or tag == stack[-1]):
            push(literal + backslashes)
            stack.pop()
        elif not closing and is_style(tag):
            push(literal + backslashes)
            stack.append(tag)
        else:
            push(literal + m.group(0))
    push(text[pos:])
    return spans


def plain(spans: Iterable[Sequence[str]]) -> str:
    """The text of a span list with styling dropped."""
    return "".join(s[0] for s in spans)


def _cell(value: Any) -> List[str]:
    """A table cell as ``[text, style]`` — the style of its first styled span."""
    spans = parse_markup(_cellify(value))
    style = next((s for _, s in spans if s), "")
    return [plain(spans), style]


# --------------------------------------------------------------------------- #
# The facade
# --------------------------------------------------------------------------- #
class CaptureOutput(Output):
    """Records output calls as events; prints nothing."""

    def __init__(self, emit: Callable[[Event], None]):
        # No super().__init__(): that would build terminal consoles we never use.
        self.quiet = False
        self._rich = True          # handlers branch on this to decide on markup
        self.console = None
        self.err_console = None
        self._emit = emit

    def _line(self, style: str, msg: Any) -> None:
        self._emit({"kind": "line", "style": style, "spans": parse_markup(msg)})

    # -- primitive lines ---------------------------------------------------- #
    def print(self, *args: Any, **kwargs: Any) -> None:
        if not args:
            self._emit({"kind": "blank"})
            return
        self._line("plain", " ".join(str(a) for a in args))

    def raw(self, s: str) -> None:
        self._emit({"kind": "raw", "text": _cellify(s)})

    def success(self, msg: str) -> None:
        self._line("success", msg)

    def info(self, msg: str) -> None:
        self._line("info", msg)

    def warn(self, msg: str) -> None:
        self._line("warn", msg)

    def error(self, msg: str) -> None:
        self._line("error", msg)

    def hint(self, msg: str) -> None:
        self._line("hint", msg)

    def rule(self, title: str = "") -> None:
        self._emit({"kind": "rule", "title": plain(parse_markup(title))})

    # -- structured widgets ------------------------------------------------- #
    def panel(self, body: str, title: str = "", style: str = "") -> None:
        self._emit({"kind": "panel", "title": plain(parse_markup(title)),
                    "spans": parse_markup(body)})

    def table(self, columns: Sequence[str], rows: Iterable[Sequence[Any]],
              title: str = "") -> None:
        self._emit({
            "kind": "table",
            "title": plain(parse_markup(title)),
            "columns": [plain(parse_markup(c)) for c in columns],
            "rows": [[_cell(x) for x in r] for r in rows],
        })

    def keyval(self, pairs: Sequence[Tuple[str, Any]], title: str = "") -> None:
        self._emit({
            "kind": "keyval",
            "title": plain(parse_markup(title)),
            "pairs": [[str(k), plain(parse_markup(_cellify(v)))] for k, v in pairs],
        })

    def markdown(self, md: str) -> None:
        self._emit({"kind": "markdown", "text": str(md)})

    def code(self, code: str, lang: str = "text") -> None:
        self._emit({"kind": "code", "text": str(code), "lang": lang})


# --------------------------------------------------------------------------- #
# Plain-text rendering (saving / copying a whole result)
# --------------------------------------------------------------------------- #
_GLYPH = {"success": "✓ ", "info": "• ", "warn": "! ", "error": "✗ ", "hint": "  "}


def events_to_text(events: Iterable[Event]) -> str:
    """Render captured events as plain text, e.g. for *Save output*."""
    out: List[str] = []
    for ev in events:
        kind = ev.get("kind")
        if kind == "line":
            out.append(_GLYPH.get(ev.get("style", ""), "") + plain(ev["spans"]))
        elif kind == "blank":
            out.append("")
        elif kind in ("raw", "markdown", "code", "stream"):
            out.append(ev["text"].rstrip("\n"))
        elif kind == "rule":
            out.append(f"──── {ev['title']} ────" if ev["title"] else "─" * 40)
        elif kind == "panel":
            if ev["title"]:
                out.append(f"== {ev['title']} ==")
            out.append(plain(ev["spans"]))
        elif kind == "keyval":
            if ev["title"]:
                out.append(f"== {ev['title']} ==")
            width = max((len(k) for k, _ in ev["pairs"]), default=0)
            out.extend(f"  {k:<{width}}  {v}" for k, v in ev["pairs"])
        elif kind == "table":
            if ev["title"]:
                out.append(f"== {ev['title']} ==")
            rows = [[c[0].replace("\n", " ") for c in r] for r in ev["rows"]]
            widths = [len(c) for c in ev["columns"]]
            for r in rows:
                for i, c in enumerate(r[:len(widths)]):
                    widths[i] = max(widths[i], len(c))
            fmt = "  ".join("{:<%d}" % w for w in widths)
            out.append(fmt.format(*ev["columns"]).rstrip())
            out.append(fmt.format(*["-" * w for w in widths]))
            for r in rows:
                r = (r + [""] * len(widths))[:len(widths)]
                out.append(fmt.format(*r).rstrip())
    return "\n".join(out) + ("\n" if out else "")

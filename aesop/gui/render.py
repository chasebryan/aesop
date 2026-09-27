"""
aesop.gui.render — draw captured output and manual pages in a Tk text widget.

:class:`RichText` is a read-only ``tk.Text`` that knows how to lay out the
event dicts from :mod:`aesop.gui.capture` (styled lines, tables, key/value
blocks, panels, the primary result) and the blocks from
:mod:`aesop.gui.markdown`.  Everything stays real, selectable text — tables are
aligned in a monospace face rather than embedded widgets — so copy and paste
behave the way they do in a terminal.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import markdown as md
from .theme import Palette, Theme

MAX_CELL = 96            # widest a table cell is drawn; the full text is kept
MAX_ROWS = 1500          # rows drawn per table
MAX_RAW = 200_000        # characters of a primary result drawn

_LINE_TAG = {"success": "good", "info": "info", "warn": "warn", "error": "bad", "hint": "muted"}
_LINE_GLYPH = {"success": "✓ ", "info": "• ", "warn": "! ", "error": "✗ ", "hint": "  "}


def display(text: str) -> str:
    """One-line, printable rendition of ``text`` for a table cell."""
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\n":
            out.append("⏎")
        elif ch == "\t":
            out.append(" ")
        elif o < 32 or 127 <= o < 160:
            out.append("·")
        else:
            out.append(ch)
    return "".join(out)


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[:width - 1] + "…"


class RichText(tk.Text):
    """Read-only styled text with links, tables and themed tags."""

    def __init__(self, master: tk.Misc, theme: Theme, **kw: Any):
        kw.setdefault("wrap", "word")
        kw.setdefault("padx", 16)
        kw.setdefault("pady", 12)
        kw.setdefault("cursor", "xterm")
        kw.setdefault("undo", False)
        super().__init__(master, font=theme.fonts["ui"], state="disabled",
                         takefocus=True, **kw)
        self.theme = theme
        self._links: Dict[str, Callable[[], None]] = {}
        self._styles: Dict[Tuple[str, bool], str] = {}   # (console style, mono) -> tag
        self._tables: List[Dict[str, Any]] = []
        self._menu = tk.Menu(self, tearoff=False)
        self._context: Optional[Tuple[Dict[str, Any], int, int]] = None
        self.on_use: Optional[Callable[[str], None]] = None     # "use as input"
        self.bind("<Button-1>", lambda _e: self.focus_set(), add="+")
        self.bind("<Button-3>", self._popup)
        self.bind("<Control-a>", self._select_all)
        self.bind("<Control-A>", self._select_all)
        theme.listen(self.apply_theme)

    # -- theming ------------------------------------------------------------ #
    def apply_theme(self, p: Palette) -> None:
        f = self.theme.fonts
        self.theme.style_text(self)
        self.configure(highlightthickness=0)
        self.theme.style_menu(self._menu)
        def cfg(tag: str, **opts: Any) -> None:
            try:
                self.tag_configure(tag, **opts)
            except tk.TclError:         # Tk < 8.6.6 lacks these cosmetic options
                for extra in ("lmargincolor", "rmargincolor", "underlinefg"):
                    opts.pop(extra, None)
                self.tag_configure(tag, **opts)

        # Order matters: later tags win.  Layout first, colour last.
        cfg("mono", font=f["mono"])
        cfg("cmdline", font=f["mono"], foreground=p.muted, spacing3=8)
        cfg("raw", font=f["mono"], background=p.raised, lmargin1=12, lmargin2=12,
            rmargin=12, spacing1=1, spacing3=1, wrap="char",
            lmargincolor=p.raised, rmargincolor=p.raised)
        cfg("rawpad", font=f["small"], background=p.raised, spacing1=0, spacing3=0)
        cfg("code", font=f["mono"], background=p.raised, lmargin1=12, lmargin2=12,
            rmargin=12, wrap="none", lmargincolor=p.raised, foreground=p.secondary)
        cfg("panel", font=f["mono"], background=p.raised, lmargin1=12, lmargin2=12,
            rmargin=12, lmargincolor=p.raised, wrap="none")
        cfg("tbl", font=f["mono"], wrap="none", lmargin1=4)
        cfg("tbl_head", font=f["mono_bold"], foreground=p.info, wrap="none", lmargin1=4,
            underline=True, underlinefg=p.border, spacing3=5)
        cfg("heading", font=f["ui_bold"], foreground=p.accent_text, spacing1=6, spacing3=3)
        cfg("key", font=f["mono_bold"], foreground=p.info, lmargin1=8)
        cfg("val", font=f["mono"], lmargin2=8)
        cfg("rule", foreground=p.border, font=f["mono"], spacing1=6, spacing3=6)
        cfg("stream", font=f["mono"], foreground=p.muted)
        cfg("status", font=f["small"], foreground=p.muted, spacing1=10)
        cfg("action", font=f["small"], foreground=p.accent_text, spacing1=3, spacing3=6)
        cfg("sep", font=f["small"], foreground=p.muted)
        # markdown
        cfg("h1", font=f["h1"], spacing1=4, spacing3=8)
        cfg("h2", font=f["h2"], spacing1=16, spacing3=6)
        cfg("h3", font=f["h3"], spacing1=12, spacing3=4, foreground=p.secondary)
        cfg("para", spacing3=8, spacing2=2)
        cfg("quote", font=f["ui_italic"], foreground=p.secondary, lmargin1=14,
            lmargin2=14, spacing3=10, spacing2=2, lmargincolor=p.surface)
        for level in range(4):
            cfg(f"li{level}", lmargin1=10 + 20 * level, lmargin2=26 + 20 * level,
                spacing3=4, spacing2=2)
        cfg("md_bold", font=f["ui_bold"])
        cfg("md_italic", font=f["ui_italic"])
        cfg("md_code", font=f["mono"], background=p.raised, foreground=p.text)
        cfg("md_code_bold", font=f["mono_bold"], background=p.raised, foreground=p.text)
        cfg("comment", foreground=p.muted)
        # colour
        cfg("muted", foreground=p.muted)
        cfg("good", foreground=p.good)
        cfg("warn", foreground=p.warn)
        cfg("bad", foreground=p.bad)
        cfg("info", foreground=p.info)
        cfg("link", foreground=p.accent_text)
        cfg("hover", underline=True)
        for (style, mono), tag in self._styles.items():
            self._configure_style(tag, style, mono)
        self.tag_raise("sel")

    def _configure_style(self, tag: str, style: str, mono: bool) -> None:
        f, p = self.theme.fonts, self.palette
        toks = style.split()
        opts: Dict[str, Any] = {}
        skip = False
        for tok in toks:
            if skip:
                skip = False
                continue
            if tok in ("on", "not"):            # backgrounds/negations are not drawn
                skip = True
            elif tok == "dim":
                opts["foreground"] = p.muted
            elif tok == "underline":
                opts["underline"] = True
            elif tok == "strike":
                opts["overstrike"] = True
            elif tok not in ("bold", "italic", "reverse", "blink"):
                opts["foreground"] = self.theme.colour(tok)
        prefix = "mono" if mono else "ui"
        if "bold" in toks:
            opts["font"] = f[f"{prefix}_bold"]
        elif "italic" in toks:
            opts["font"] = f[f"{prefix}_italic"]
        self.tag_configure(tag, **opts)

    @property
    def palette(self) -> Palette:
        return self.theme.palette

    def style_tag(self, style: str, mono: bool = False) -> str:
        """The tag for a console style such as ``bold red`` (created on demand)."""
        if not style:
            return ""
        tag = self._styles.get((style, mono))
        if tag is None:
            tag = self._styles[(style, mono)] = f"style{len(self._styles)}"
            self._configure_style(tag, style, mono)
            self.tag_raise("sel")
        return tag

    # -- primitives --------------------------------------------------------- #
    def put(self, text: str, *tags: str) -> None:
        self.configure(state="normal")
        self.insert("end", text, tuple(t for t in tags if t))
        self.configure(state="disabled")

    def clear(self) -> None:
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")
        for tag in self._links:
            self.tag_delete(tag)
        self._links.clear()
        self._tables.clear()

    def link(self, text: str, callback: Callable[[], None], *tags: str) -> None:
        """Insert clickable ``text``."""
        tag = f"link{len(self._links)}"
        self._links[tag] = callback
        self.tag_bind(tag, "<Button-1>", lambda _e, cb=callback: (cb(), "break")[1])
        self.tag_bind(tag, "<Enter>", lambda _e, t=tag: self._hover(t, True))
        self.tag_bind(tag, "<Leave>", lambda _e, t=tag: self._hover(t, False))
        self.put(text, *tags, "link", tag)

    def _hover(self, tag: str, on: bool) -> None:
        self.configure(cursor="hand2" if on else "xterm")
        self.tag_configure(tag, underline=on)

    def _select_all(self, _event: tk.Event) -> str:
        self.tag_add("sel", "1.0", "end-1c")
        return "break"

    def _end_line(self) -> int:
        """Line number where the next insert will land."""
        return int(self.index("end-1c").split(".")[0])

    def _fresh_line(self) -> None:
        if self.index("end-1c").split(".")[1] != "0":
            self.put("\n")

    # -- capture events ----------------------------------------------------- #
    def add_event(self, ev: Dict[str, Any]) -> None:
        handler = getattr(self, f"_ev_{ev.get('kind')}", None)
        if handler is not None:
            handler(ev)

    def _spans(self, spans: Sequence[Sequence[str]], *base: str, mono: bool = False) -> None:
        for text, style in spans:
            self.put(text, *base, self.style_tag(style, mono))

    def _ev_line(self, ev: Dict[str, Any]) -> None:
        self._fresh_line()
        kind = ev.get("style", "plain")
        tag = _LINE_TAG.get(kind, "")
        if kind in _LINE_GLYPH:
            self.put(_LINE_GLYPH[kind], tag)
        # errors and hints colour the whole line; the rest only the glyph
        self._spans(ev["spans"], tag if kind in ("error", "hint") else "")
        self.put("\n")

    def _ev_blank(self, _ev: Dict[str, Any]) -> None:
        self._fresh_line()
        self.put("\n")

    def _ev_raw(self, ev: Dict[str, Any]) -> None:
        self._fresh_line()
        text = ev["text"].rstrip("\n")
        shown = text[:MAX_RAW]
        self.put("\n", "rawpad")
        self.put(shown + "\n", "raw")
        self.put("\n", "rawpad")
        if len(text) > MAX_RAW:
            self.put(f"… {len(text) - MAX_RAW:,} more characters not shown — "
                     "copy or save for the full result\n", "muted")
        self._actions(text)

    def _actions(self, text: str) -> None:
        self.link("Copy", lambda: self.copy(text), "action")
        if self.on_use is not None:
            self.put("   ·   ", "sep")
            self.link("Use as input", lambda: self.on_use and self.on_use(text), "action")
        self.put("\n", "action")

    def _ev_rule(self, ev: Dict[str, Any]) -> None:
        self._fresh_line()
        title = ev.get("title", "")
        if title:
            self.put("── ", "rule")
            self.put(title, "heading")
            self.put(" " + "─" * 48 + "\n", "rule")
        else:
            self.put("─" * 60 + "\n", "rule")

    def _ev_panel(self, ev: Dict[str, Any]) -> None:
        self._fresh_line()
        if ev.get("title"):
            self.put(ev["title"] + "\n", "heading")
        self.put("\n", "rawpad")
        self._spans(ev["spans"], "panel", mono=True)
        self.put("\n", "panel")
        self.put("\n", "rawpad")

    def _ev_code(self, ev: Dict[str, Any]) -> None:
        self._fresh_line()
        self.put("\n", "rawpad")
        self.put(ev["text"].rstrip("\n") + "\n", "code")
        self.put("\n", "rawpad")

    def _ev_stream(self, ev: Dict[str, Any]) -> None:
        self.put(ev["text"], "stream")

    def _ev_markdown(self, ev: Dict[str, Any]) -> None:
        self._fresh_line()
        self.add_markdown(md.parse(ev["text"]))

    def _ev_keyval(self, ev: Dict[str, Any]) -> None:
        self._fresh_line()
        if ev.get("title"):
            self.put(ev["title"] + "\n", "heading")
        width = max((len(k) for k, _ in ev["pairs"]), default=0)
        for k, v in ev["pairs"]:
            self.put(f"{k:<{width}}  ", "key")
            self.put(f"{v}\n", "val")

    def _ev_table(self, ev: Dict[str, Any]) -> None:
        rows = [[(str(c[0]), c[1] if len(c) > 1 else "") for c in r] for r in ev["rows"]]
        self.add_table(ev.get("title", ""), ev["columns"], rows)

    # -- tables ------------------------------------------------------------- #
    def add_table(self, title: str, columns: Sequence[str],
                  rows: Sequence[Sequence[Tuple[str, str]]]) -> None:
        self._fresh_line()
        if title:
            self.put(title + "\n", "heading")
        ncols = max([len(columns)] + [len(r) for r in rows]) if (columns or rows) else 0
        if not ncols:
            return
        columns = list(columns) + [""] * (ncols - len(columns))
        drawn = rows[:MAX_ROWS]
        cells = [[display(r[i][0]) if i < len(r) else "" for i in range(ncols)] for r in drawn]
        widths = [min(MAX_CELL, max([len(columns[i])] + [len(c[i]) for c in cells]))
                  for i in range(ncols)]
        # right-align columns that are entirely numeric
        numeric = [bool(cells) and all(_is_number(c[i]) for c in cells) for i in range(ncols)]
        starts, x = [], 0
        for w in widths:
            starts.append(x)
            x += w + 2

        def fmt(i: int, text: str) -> str:
            text = _clip(text, widths[i])
            return text.rjust(widths[i]) if numeric[i] else text.ljust(widths[i])

        self.put("  ".join(fmt(i, c) for i, c in enumerate(columns)), "tbl_head")
        self.put("\n", "tbl")
        first = self._end_line()
        for r, row in zip(drawn, cells):
            for i, text in enumerate(row):
                style = r[i][1] if i < len(r) else ""
                last = i == ncols - 1
                piece = fmt(i, text)
                self.put(piece.rstrip() if last else piece + "  ", "tbl",
                         self.style_tag(style, mono=True))
            self.put("\n", "tbl")
        self._tables.append({"first": first, "count": len(drawn), "starts": starts,
                             "widths": widths, "rows": drawn, "columns": columns})
        if len(rows) > MAX_ROWS:
            self.put(f"… {len(rows) - MAX_ROWS:,} more rows — save the output to see them all\n",
                     "muted")

    def _cell_at(self, x: int, y: int) -> Optional[Tuple[Dict[str, Any], int, int]]:
        line, col = (int(v) for v in self.index(f"@{x},{y}").split("."))
        for t in self._tables:
            if t["first"] <= line < t["first"] + t["count"]:
                row = line - t["first"]
                hit = 0
                for i, start in enumerate(t["starts"]):
                    if col >= start:
                        hit = i
                return t, row, hit
        return None

    # -- context menu / clipboard ------------------------------------------- #
    def copy(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

    def selection_text(self) -> str:
        try:
            return self.get("sel.first", "sel.last")
        except tk.TclError:
            return ""

    def _popup(self, event: tk.Event) -> None:
        m = self._menu
        m.delete(0, "end")
        sel = self.selection_text()
        if sel:
            m.add_command(label="Copy selection", command=lambda: self.copy(sel))
            if self.on_use is not None:
                m.add_command(label="Use selection as input",
                              command=lambda: self.on_use and self.on_use(sel))
        hit = self._cell_at(event.x, event.y)
        if hit is not None:
            table, r, c = hit
            row = table["rows"][r]
            if c < len(row):
                cell = row[c][0]
                name = table["columns"][c] or "cell"
                if sel:
                    m.add_separator()
                m.add_command(label=f"Copy {name}", command=lambda: self.copy(cell))
                if self.on_use is not None:
                    m.add_command(label=f"Use {name} as input",
                                  command=lambda: self.on_use and self.on_use(cell))
                m.add_command(label="Copy row",
                              command=lambda: self.copy("\t".join(x[0] for x in row)))
        if m.index("end") is not None:
            m.add_separator()
        m.add_command(label="Select all", command=lambda: self._select_all(event))
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()

    # -- markdown ----------------------------------------------------------- #
    def add_markdown(self, blocks: Sequence[md.Block],
                     resolve: Optional[Callable[[str], Optional[Callable[[], None]]]] = None
                     ) -> None:
        """Lay out parsed Markdown.  ``resolve(code)`` may turn a piece of code
        (``aesop manual xor``, an example command) into a click action."""
        for b in blocks:
            if b.kind == "heading":
                tag = f"h{min(b.level, 3)}"
                self._inline(b.spans, resolve, tag)
                self.put("\n", tag)
            elif b.kind == "para":
                self._inline(b.spans, resolve, "para")
                self.put("\n", "para")
            elif b.kind == "quote":
                self._inline(b.spans, resolve, "quote")
                self.put("\n", "quote")
            elif b.kind == "item":
                tag = f"li{min(b.level, 3)}"
                self.put(f"{b.marker} ", tag, "muted")
                self._inline(b.spans, resolve, tag)
                self.put("\n", tag)
            elif b.kind == "rule":
                self.put("─" * 60 + "\n", "rule")
            elif b.kind == "code":
                self._code_block(b, resolve)
            elif b.kind == "table":
                rows = [[(md.inline_text(c), "") for c in r] for r in b.rows]
                self.add_table("", [md.inline_text(c) for c in b.header], rows)
                self.put("\n", "para")

    def _inline(self, spans: Sequence[md.Inline], resolve, base: str) -> None:
        for text, styles, href in spans:
            tags = [base]
            if "code" in styles:
                tags.append("md_code_bold" if "bold" in styles else "md_code")
            elif "bold" in styles:
                tags.append("md_bold")
            elif "italic" in styles:
                tags.append("md_italic")
            action = None
            if resolve is not None and ("code" in styles or href):
                action = resolve(href or text)
            if action is not None:
                self.link(text, action, *tags)
            else:
                self.put(text, *tags)

    def _code_block(self, b: md.Block, resolve) -> None:
        self.put("\n", "rawpad")
        for line in b.text.split("\n"):
            stripped = line.strip()
            action = None
            if resolve is not None and b.lang in ("console", "bash", "sh", "") \
                    and "aesop" in stripped:
                action = resolve(stripped)
            if stripped.startswith("#"):
                self.put(line, "code", "comment")
            elif action is not None:
                self.link(line, action, "code")
            else:
                self.put(line, "code")
            self.put("\n", "code")
        self.put("\n", "rawpad")
        self.put("\n", "para")


def _is_number(text: str) -> bool:
    t = text.strip().rstrip("%")
    if not t:
        return False
    try:
        float(t.replace(",", ""))
        return True
    except ValueError:
        return False


class ScrolledText(ttk.Frame):
    """A :class:`RichText` with auto-hiding scrollbars."""

    def __init__(self, master: tk.Misc, theme: Theme, **kw: Any):
        super().__init__(master, style="Surface.TFrame")
        self.text = RichText(self, theme, **kw)
        self._v = ttk.Scrollbar(self, orient="vertical", command=self.text.yview,
                                style="Surface.Vertical.TScrollbar")
        self._h = ttk.Scrollbar(self, orient="horizontal", command=self.text.xview,
                                style="Surface.Horizontal.TScrollbar")
        self.text.configure(yscrollcommand=lambda a, b: self._set(self._v, a, b, 0, 1),
                            xscrollcommand=lambda a, b: self._set(self._h, a, b, 1, 0))
        self.text.grid(row=0, column=0, sticky="nsew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

    def _set(self, bar: ttk.Scrollbar, first: str, last: str, row: int, col: int) -> None:
        bar.set(first, last)
        if float(first) <= 0.0 and float(last) >= 1.0:
            bar.grid_remove()
        else:
            bar.grid(row=row, column=col, sticky="ns" if col else "ew")

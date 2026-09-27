"""
aesop.gui.widgets — the workbench's building blocks.

* :class:`ScrollFrame`      — a vertically scrolling container.
* :class:`PlaceholderEntry` — an entry with greyed hint text.
* :class:`CommandForm`      — a command's options, generated from the registry.
* :class:`Inspector`        — live statistics and charts for the input.
"""
from __future__ import annotations

import re
import tkinter as tk
from tkinter import filedialog, ttk
from typing import Any, Callable, Dict, List, Optional

from ..registry import Command, resolve
from . import forms
from .charts import ByteChart, EntropyChart, LetterChart
from .insight import Insight, english_frequencies
from .theme import Theme


# "aesop b64 -d --url", "aesop vigenere / aesop transposition", …
_SUGGESTED = re.compile(r"aesop\s+([\w-]+)((?:\s+-{1,2}[A-Za-z][\w-]*)*)")


def bind_wheel(widget: tk.Misc, target: tk.Canvas) -> None:
    """Make the mouse wheel over ``widget`` (and its children) scroll ``target``."""
    def scroll(units: int) -> str:
        first, last = target.yview()
        if first > 0.0 or last < 1.0:
            target.yview_scroll(units, "units")
        return "break"

    if not isinstance(widget, (tk.Text, ttk.Combobox, tk.Listbox)):
        widget.bind("<MouseWheel>", lambda e: scroll(-1 if e.delta > 0 else 1), add="+")
        widget.bind("<Button-4>", lambda _e: scroll(-1), add="+")
        widget.bind("<Button-5>", lambda _e: scroll(1), add="+")
    for child in widget.winfo_children():
        bind_wheel(child, target)


def autoscroll(widget: tk.Widget, bar: ttk.Scrollbar, **pack: Any) -> ttk.Scrollbar:
    """Attach a vertical scrollbar that is only packed while there is overflow."""
    def update(first: str, last: str) -> None:
        bar.set(first, last)
        if float(first) <= 0.0 and float(last) >= 1.0:
            bar.pack_forget()
        elif not bar.winfo_ismapped():
            bar.pack(**pack)

    bar.configure(command=widget.yview)
    widget.configure(yscrollcommand=update)
    return bar


class ScrollFrame(ttk.Frame):
    """A frame whose ``.body`` scrolls vertically when it outgrows the space."""

    def __init__(self, master: tk.Misc, theme: Theme):
        super().__init__(master)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0, height=10)
        self.bar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.body = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        self.canvas.configure(yscrollcommand=self._on_scroll)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.body.bind("<Configure>", self._on_body)
        self.canvas.bind("<Configure>", self._on_canvas)
        theme.listen(lambda p: self.canvas.configure(background=p.bg))

    def _on_body(self, _event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas(self, event: tk.Event) -> None:
        self.canvas.itemconfigure(self._win, width=event.width)

    def _on_scroll(self, first: str, last: str) -> None:
        self.bar.set(first, last)
        if float(first) <= 0.0 and float(last) >= 1.0:
            self.bar.grid_remove()
        else:
            self.bar.grid(row=0, column=1, sticky="ns")

    def refresh(self) -> None:
        """Call after (re)building the body."""
        bind_wheel(self.body, self.canvas)
        self.canvas.yview_moveto(0)


class PlaceholderEntry(ttk.Entry):
    """An entry showing muted hint text while empty and unfocused."""

    def __init__(self, master: tk.Misc, theme: Theme, placeholder: str, **kw: Any):
        self.var = tk.StringVar()
        super().__init__(master, textvariable=self.var, **kw)
        self._theme = theme
        self._placeholder = placeholder
        self._showing = False
        self.bind("<FocusIn>", self._focus_in, add="+")
        self.bind("<FocusOut>", self._focus_out, add="+")
        theme.listen(lambda _p: self._recolour())
        self._focus_out()

    def _recolour(self) -> None:
        p = self._theme.palette
        self.configure(foreground=p.muted if self._showing else p.text)

    def _focus_in(self, _event: Optional[tk.Event] = None) -> None:
        if self._showing:
            self._showing = False
            self.var.set("")
            self._recolour()

    def _focus_out(self, _event: Optional[tk.Event] = None) -> None:
        if not self.var.get():
            self._showing = True
            self.var.set(self._placeholder)
            self._recolour()

    def value(self) -> str:
        return "" if self._showing else self.var.get()

    def set_value(self, text: str) -> None:
        self._showing = False
        self.var.set(text)
        self._recolour()
        if not text and self.focus_get() is not self:
            self._focus_out()


# --------------------------------------------------------------------------- #
# The options form
# --------------------------------------------------------------------------- #
class CommandForm(ttk.Frame):
    """Widgets for a command's options, built from its registry ``Arg`` specs.

    ``skip`` names the fields drawn elsewhere (the shared input box, file and
    encoding controls).  Values are exchanged as the plain dict that
    :func:`aesop.gui.forms.build_argv` consumes.
    """

    def __init__(self, master: tk.Misc, theme: Theme,
                 on_change: Callable[[], None]):
        super().__init__(master)
        self.theme = theme
        self._on_change = on_change
        self._vars: Dict[str, tk.Variable] = {}
        self._fields: List[forms.Field] = []
        self._help: List[ttk.Label] = []
        self._boxes: List[ttk.Combobox] = []
        self._muted = False            # suppress change callbacks while loading
        self.columnconfigure(2, weight=1)
        self.bind("<Configure>", self._wrap_help)
        theme.listen(lambda _p: [theme.style_combobox(b) for b in self._boxes])

    # -- building ----------------------------------------------------------- #
    def build(self, cmd: Command, skip: List[str]) -> None:
        for child in self.winfo_children():
            child.destroy()
        self._vars.clear()
        self._help.clear()
        self._boxes.clear()
        self._fields = [f for f in forms.fields_for(cmd) if f.dest not in skip]
        for row, f in enumerate(self._fields):
            self._row(row, f)
        if not self._fields:
            ttk.Label(self, text="This command has no options.", style="Muted.TLabel") \
                .grid(row=0, column=0, columnspan=3, sticky="w", pady=4)

    def _row(self, row: int, f: forms.Field) -> None:
        label = f.label + (" *" if f.required else "")
        ttk.Label(self, text=label, style="Flag.TLabel") \
            .grid(row=row, column=0, sticky="nw", padx=(0, 14), pady=5)

        if f.kind == forms.FLAG:
            var: tk.Variable = tk.BooleanVar(value=False)
            widget: tk.Widget = ttk.Checkbutton(self, variable=var, takefocus=True)
        elif f.kind == forms.CHOICE:
            var = tk.StringVar(value="" if f.default is None else str(f.default))
            widget = ttk.Combobox(self, textvariable=var, values=f.choices,
                                  state="readonly", width=20)
            self._boxes.append(widget)
        elif f.kind in (forms.PATH, forms.DIR):
            var = tk.StringVar()
            widget = ttk.Frame(self)
            entry = ttk.Entry(widget, textvariable=var, width=24, font=self.theme.fonts["mono"])
            entry.pack(side="left")
            ttk.Button(widget, text="Browse…", style="Ghost.TButton",
                       command=lambda v=var, k=f.kind: self._browse(v, k)) \
                .pack(side="left", padx=(4, 0))
        else:
            var = tk.StringVar(value="" if f.default is None else str(f.default))
            width = 30 if f.kind in (forms.LIST, forms.TEXT) else 12
            widget = ttk.Entry(self, textvariable=var, width=width,
                               font=self.theme.fonts["mono"])
        widget.grid(row=row, column=1, sticky="w", pady=3)
        var.trace_add("write", self._changed)
        self._vars[f.dest] = var

        text = f.help
        if f.kind == forms.LIST:
            text += "  (separate several values with spaces)"
        help_label = ttk.Label(self, text=text, style="Muted.TLabel", justify="left")
        help_label.grid(row=row, column=2, sticky="nw", padx=(14, 0), pady=5)
        self._help.append(help_label)

    def _browse(self, var: tk.StringVar, kind: str) -> None:
        if kind == forms.DIR:
            path = filedialog.askdirectory(parent=self, title="Choose a folder")
        else:
            path = filedialog.askopenfilename(parent=self, title="Choose a file")
        if path:
            var.set(path)

    def _wrap_help(self, _event: tk.Event) -> None:
        if not self._help:
            return
        self.update_idletasks()
        x = self._help[0].winfo_x()
        width = max(120, self.winfo_width() - x - 8)
        for lab in self._help:
            lab.configure(wraplength=width)

    def _changed(self, *_a: Any) -> None:
        if not self._muted:
            self._on_change()

    # -- values ------------------------------------------------------------- #
    def values(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for f in self._fields:
            v = self._vars[f.dest].get()
            out[f.dest] = v if f.kind == forms.FLAG else str(v).strip() \
                if f.kind != forms.TEXT else str(v)
        return out

    def set_values(self, values: Dict[str, Any]) -> None:
        """Load ``values``; fields not mentioned return to their defaults."""
        self._muted = True
        try:
            for f in self._fields:
                var = self._vars[f.dest]
                if f.dest in values and values[f.dest] is not None:
                    v = values[f.dest]
                    if f.kind == forms.FLAG:
                        var.set(bool(v))
                    elif isinstance(v, (list, tuple)):
                        var.set(" ".join(str(x) for x in v))
                    else:
                        var.set(str(v))
                elif f.kind == forms.FLAG:
                    var.set(False)
                else:
                    var.set("" if f.default is None else str(f.default))
        finally:
            self._muted = False
        self._on_change()


# --------------------------------------------------------------------------- #
# The inspector
# --------------------------------------------------------------------------- #
class _Stat(ttk.Frame):
    def __init__(self, master: tk.Misc, label: str):
        super().__init__(master)
        ttk.Label(self, text=label, style="Small.TLabel").pack(anchor="w")
        self.value = ttk.Label(self, text="—", style="Stat.TLabel")
        self.value.pack(anchor="w")
        self.note = ttk.Label(self, text="", style="Small.TLabel", wraplength=140,
                              justify="left")
        self.note.pack(anchor="w")

    def set(self, value: str, note: str = "") -> None:
        self.value.configure(text=value)
        self.note.configure(text=note)


class Inspector(ttk.Frame):
    """What the input looks like, at a glance — updated as you type."""

    def __init__(self, master: tk.Misc, theme: Theme,
                 on_suggest: Callable[[str], None]):
        super().__init__(master, padding=(14, 10, 14, 10), width=330)
        self.pack_propagate(False)
        self.theme = theme
        self._on_suggest = on_suggest
        ttk.Label(self, text="Inspector", style="Section.TLabel").pack(anchor="w")

        grid = ttk.Frame(self)
        grid.pack(fill="x", pady=(8, 4))
        grid.columnconfigure((0, 1), weight=1, uniform="stat")
        self.length = _Stat(grid, "Length")
        self.entropy = _Stat(grid, "Entropy (bits/byte)")
        self.ic = _Stat(grid, "Index of coincidence")
        self.printable = _Stat(grid, "Printable")
        for i, tile in enumerate((self.length, self.entropy, self.ic, self.printable)):
            tile.grid(row=i // 2, column=i % 2, sticky="nw", pady=6, padx=(0, 8))

        ttk.Separator(self).pack(fill="x", pady=8)
        ttk.Label(self, text="Looks like", style="Section.TLabel").pack(anchor="w")
        self.guesses = ttk.Frame(self)
        self.guesses.pack(fill="x", pady=(4, 0))

        ttk.Separator(self).pack(fill="x", pady=8)
        self.charts = ttk.Frame(self)
        self.charts.pack(fill="both", expand=True)
        self.letters = LetterChart(self.charts, theme)
        self.bytes = ByteChart(self.charts, theme)
        self.entropy_chart = EntropyChart(self.charts, theme)
        self._shown: List[tk.Widget] = []
        self.show(Insight())

    def show(self, info: Insight) -> None:
        for child in self.guesses.winfo_children():
            child.destroy()

        if info.error:
            for tile in (self.length, self.entropy, self.ic, self.printable):
                tile.set("—")
            ttk.Label(self.guesses, text=info.error, style="Bad.TLabel", wraplength=290,
                      justify="left").pack(anchor="w")
            self._charts([])
            return
        if info.empty:
            for tile in (self.length, self.entropy, self.ic, self.printable):
                tile.set("—")
            ttk.Label(self.guesses, text="Type, paste or open some input to see what "
                      "it looks like.", style="Muted.TLabel", wraplength=290,
                      justify="left").pack(anchor="w")
            self._charts([])
            return

        unit = "byte" if info.size == 1 else "bytes"
        decoded = {"raw": "as typed", "bytes": "raw bytes"}.get(
            info.encoding, f"decoded from {info.encoding}")
        if info.sniffed:
            decoded += f"; solvers will decode it as {info.sniffed}"
        if info.sampled < info.size:
            decoded += f"; first {info.sampled:,} analysed"
        self.length.set(f"{info.size:,} {unit}", decoded)
        self.entropy.set(f"{info.entropy:.2f}", info.entropy_reading)
        self.ic.set("—" if info.ic is None else f"{info.ic:.4f}", info.ic_reading)
        self.printable.set(f"{info.printable:.0%}", f"{info.letters:,} letters")

        for g in info.guesses[:3]:
            self._guess(g)

        charts: List[tk.Widget] = []
        if info.texty:
            self.letters.set_data(info.letter_freq, english_frequencies())
            charts.append(self.letters)
        else:
            self.bytes.set_data(info.byte_counts)
            charts.append(self.bytes)
        self.entropy_chart.set_data(info.entropy_series, info.size)
        if self.entropy_chart.has_data():
            charts.append(self.entropy_chart)
        self._charts(charts)

    def _guess(self, g: Any) -> None:
        row = ttk.Frame(self.guesses)
        row.pack(fill="x", pady=3)
        head = ttk.Frame(row)
        head.pack(fill="x")
        ttk.Label(head, text=g.label, font=self.theme.fonts["ui_bold"]).pack(side="left")
        ttk.Label(head, text=f"{g.confidence:.0%}", style="Muted.TLabel").pack(side="right")
        ttk.Label(row, text=g.reason, style="Small.TLabel", wraplength=290,
                  justify="left").pack(anchor="w")
        links = ttk.Frame(row)
        links.pack(anchor="w")
        for name, flags in _SUGGESTED.findall(g.suggest or "")[:3]:
            if resolve(name) is None:
                continue
            line = f"aesop {name}{flags}"
            link = ttk.Label(links, text=f"Try {name}{flags} →", style="Link.TLabel",
                             cursor="hand2", font=self.theme.fonts["small"])
            link.pack(side="left", padx=(0, 12))
            link.bind("<Button-1>", lambda _e, s=line: self._on_suggest(s))

    def _charts(self, charts: List[tk.Widget]) -> None:
        for c in self._shown:
            c.pack_forget()
        self._shown = charts
        for c in charts:
            c.pack(fill="x", pady=(0, 10))

"""
aesop.gui.views — the workbench's secondary tabs.

* :class:`ManualView`  — the field guide, browsable and searchable.
* :class:`HistoryView` — every run this session, restorable.
"""
from __future__ import annotations

import time
import tkinter as tk
from dataclasses import dataclass, field
from tkinter import ttk
from typing import Any, Callable, Dict, List, Optional

from ..manual import get_page, load_manual, search_manual
from . import forms
from . import markdown as md
from .render import ScrolledText
from .theme import Theme
from .widgets import PlaceholderEntry, autoscroll

Resolver = Callable[[str], Optional[Callable[[], None]]]


@dataclass
class Run:
    """One execution: what was asked, and everything that came back."""

    argv: List[str]
    command: str = ""                          # canonical command name, if any
    values: Optional[Dict[str, Any]] = None    # the form state, when run from the form
    events: List[Dict[str, Any]] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    code: Optional[int] = None                 # None while running
    elapsed: float = 0.0
    cancelled: bool = False

    @property
    def result(self) -> Optional[str]:
        """The primary result — the last thing the command wrote with ``out.raw``."""
        for ev in reversed(self.events):
            if ev.get("kind") == "raw":
                return ev["text"]
        return None

    @property
    def outcome(self) -> str:
        if self.code is None:
            return "running"
        if self.cancelled:
            return "stopped"
        return "ok" if self.code == 0 else f"exit {self.code}"


def format_elapsed(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    return f"{int(seconds // 60)} min {seconds % 60:.0f} s"


class ManualView(ttk.Frame):
    def __init__(self, master: tk.Misc, theme: Theme, resolve: Resolver):
        super().__init__(master)
        self.theme = theme
        self._resolve = resolve
        self.slug: Optional[str] = None

        side = ttk.Frame(self, padding=(10, 10, 4, 10))
        side.grid(row=0, column=0, sticky="ns")
        self.search = PlaceholderEntry(side, theme, "Search the field guide", width=28)
        self.search.pack(fill="x")
        self.search.var.trace_add("write", lambda *_a: self._fill())
        holder = ttk.Frame(side)
        holder.pack(fill="both", expand=True, pady=(8, 0))
        self.topics = ttk.Treeview(holder, show="tree", selectmode="browse", height=10)
        self.topics.column("#0", width=230, stretch=True)
        self.topics.pack(side="left", fill="both", expand=True)
        autoscroll(self.topics, ttk.Scrollbar(holder, orient="vertical"),
                   side="right", fill="y")
        self.topics.bind("<<TreeviewSelect>>", self._on_select)

        self.page = ScrolledText(self, theme, padx=28, pady=20)
        self.page.grid(row=0, column=1, sticky="nsew", padx=(4, 10), pady=10)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self._fill()

    def _fill(self, force: bool = False) -> None:
        term = self.search.value().strip()
        if term == getattr(self, "_term", None) and not force:
            return                  # e.g. the placeholder text coming and going
        self._term = term
        pages = search_manual(term) if term else list(load_manual().values())
        self.topics.delete(*self.topics.get_children())
        for p in sorted(pages, key=lambda p: (p.slug != "getting-started", p.title.lower())):
            self.topics.insert("", "end", iid=p.slug, text=p.title.split(" — ")[0])
        if self.slug and self.topics.exists(self.slug):
            self.topics.selection_set(self.slug)

    def _on_select(self, _event: tk.Event) -> None:
        sel = self.topics.selection()
        if sel and sel[0] != self.slug:
            self.show(sel[0])

    def show(self, slug: str) -> bool:
        """Display the page for ``slug``.  False if there is no such page."""
        page = get_page(slug)
        if page is None:
            return False
        self.slug = page.slug
        text = self.page.text
        text.clear()
        text.add_markdown(md.parse(page.body()), self._resolve)
        text.yview_moveto(0)
        if not self.topics.exists(page.slug):
            self.search.set_value("")
            self._fill()
        if self.topics.exists(page.slug) and self.topics.selection() != (page.slug,):
            self.topics.selection_set(page.slug)
            self.topics.see(page.slug)
        return True


class HistoryView(ttk.Frame):
    def __init__(self, master: tk.Misc, theme: Theme,
                 on_restore: Callable[[Run], None], on_rerun: Callable[[Run], None]):
        super().__init__(master, padding=10)
        self.theme = theme
        self._on_restore = on_restore
        self._on_rerun = on_rerun
        self.runs: List[Run] = []

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="Runs this session — double-click to bring one back",
                  style="Muted.TLabel").pack(side="left")
        ttk.Button(bar, text="Clear", style="Ghost.TButton", command=self.clear) \
            .pack(side="right")
        self._rerun = ttk.Button(bar, text="Run again", command=self._do_rerun, state="disabled")
        self._rerun.pack(side="right", padx=6)
        self._restore = ttk.Button(bar, text="Restore", command=self._do_restore,
                                   state="disabled")
        self._restore.pack(side="right")

        cols = ("when", "command", "result", "time")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse",
                                 style="Mono.Treeview")
        for col, title, width, stretch, anchor in (
                ("when", "When", 90, False, "w"), ("command", "Command", 600, True, "w"),
                ("result", "Result", 90, False, "w"), ("time", "Took", 90, False, "e")):
            self.tree.heading(col, text=title, anchor=anchor)
            self.tree.column(col, width=width, stretch=stretch, anchor=anchor)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._sync())
        self.tree.bind("<Double-1>", lambda _e: self._do_restore())
        self.tree.bind("<Return>", lambda _e: self._do_restore())
        theme.listen(lambda p: (self.tree.tag_configure("bad", foreground=p.bad),
                                self.tree.tag_configure("stopped", foreground=p.muted)))

    def add(self, run: Run) -> None:
        self.runs.append(run)
        del self.runs[:-200]
        tag = "stopped" if run.cancelled else "bad" if run.code else ""
        self.tree.insert("", 0, iid=str(id(run)), tags=(tag,), values=(
            time.strftime("%H:%M:%S", time.localtime(run.started)),
            forms.command_line(run.argv, max_arg=120),
            run.outcome, format_elapsed(run.elapsed)))
        for iid in self.tree.get_children()[200:]:
            self.tree.delete(iid)

    def clear(self) -> None:
        self.runs.clear()
        self.tree.delete(*self.tree.get_children())
        self._sync()

    def selected(self) -> Optional[Run]:
        sel = self.tree.selection()
        if not sel:
            return None
        return next((r for r in self.runs if str(id(r)) == sel[0]), None)

    def _sync(self) -> None:
        state = "normal" if self.selected() is not None else "disabled"
        self._restore.configure(state=state)
        self._rerun.configure(state=state)

    def _do_restore(self) -> None:
        run = self.selected()
        if run is not None:
            self._on_restore(run)

    def _do_rerun(self) -> None:
        run = self.selected()
        if run is not None:
            self._on_rerun(run)

"""
aesop.gui.app — the workbench window.

Layout::

    ┌──────────┬───────────────────────────────────────┬─────────────┐
    │ commands │ Workbench │ Field guide │ History      │             │
    │ (search) ├───────────────────────────────────────┤  inspector  │
    │          │ command · input · options · examples  │  (stats and │
    │          ├───────────────────────────────────────┤   charts)   │
    │          │ output                                │             │
    │          │ aesop » command bar                   │             │
    └──────────┴───────────────────────────────────────┴─────────────┘

The input box is a shared workspace: it stays put as you move between
commands, and any result can be sent back into it, so a multi-step solve
(identify → decode → break) is a few clicks.
"""
from __future__ import annotations

import json
import os
import queue
import re
import shlex
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Dict, List, Optional

from .. import __version__, cli
from ..manual import get_page
from ..registry import GROUPS, REGISTRY, Command, commands_by_group, resolve
from . import forms
from .capture import events_to_text
from .insight import analyse
from .render import ScrolledText
from .runner import Runner
from .theme import Palette, Theme
from .views import HistoryView, ManualView, Run, format_elapsed
from .widgets import CommandForm, Inspector, PlaceholderEntry, ScrollFrame, autoscroll

ENCODINGS = ["auto", "raw", "hex", "base64", "base64url"]
POLL_MS = 25
DEFAULT_COMMAND = "auto"
_MANUAL_REF = re.compile(r"^aesop\s+(?:manual|man)\s+([\w-]+)$")


def default_prefs_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.environ.get("APPDATA") \
        or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "aesop", "gui.json")


class Prefs(dict):
    """Small persisted settings (theme, window size, last command)."""

    def __init__(self, path: Optional[str]):
        super().__init__(theme="dark", geometry="1360x860", command=DEFAULT_COMMAND,
                         inspector=True)
        self.path = path
        if path:
            try:
                with open(path, encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict):
                    self.update(loaded)
            except (OSError, ValueError):
                pass

    def save(self) -> None:
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(dict(self), fh, indent=2)
        except OSError:
            pass


class Workbench:
    def __init__(self, root: tk.Tk, *, prefs_path: Optional[str] = None,
                 theme: Optional[str] = None, command: Optional[str] = None):
        cli._load_modules()
        self.root = root
        self.prefs = Prefs(prefs_path)
        if theme:
            self.prefs["theme"] = theme
        self.theme = Theme(root, self.prefs["theme"])

        self.events: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.runner = Runner(self.events.put)
        self.cmd: Optional[Command] = None
        self.run_record: Optional[Run] = None       # the run in flight
        self.shown: Optional[Run] = None            # the run in the output pane
        self._run_id: Optional[int] = None
        self._after: Dict[str, str] = {}            # pending debounced callbacks
        self._bar_history: List[str] = []
        self._bar_pos = 0
        self._closed = False
        self._loading = False

        root.title("AESOP workbench")
        root.geometry(self.prefs["geometry"])
        root.minsize(1000, 640)
        root.protocol("WM_DELETE_WINDOW", self.close)

        self._build_menu()
        self._build_layout()
        self._bind_keys()
        self.theme.listen(self._apply_theme)

        self._fill_tree()
        start = resolve(command or "") or resolve(self.prefs["command"]) \
            or resolve(DEFAULT_COMMAND) or next(iter(REGISTRY.values()), None)
        if start is not None:
            self.select_command(start.name)
        self.set_status("Starting the worker…")
        self.runner.start()
        self._poll()

    # ======================================================================= #
    # Construction
    # ======================================================================= #
    def _build_menu(self) -> None:
        self.menubar = tk.Menu(self.root, tearoff=False)
        self.menus: List[tk.Menu] = [self.menubar]

        def menu(label: str) -> tk.Menu:
            m = tk.Menu(self.menubar, tearoff=False)
            self.menubar.add_cascade(label=label, menu=m)
            self.menus.append(m)
            return m

        m = menu("File")
        m.add_command(label="Open input file…", accelerator="Ctrl+O", command=self.open_file)
        m.add_command(label="Save output…", accelerator="Ctrl+S", command=self.save_output)
        m.add_separator()
        m.add_command(label="Quit", accelerator="Ctrl+Q", command=self.close)

        m = menu("Run")
        m.add_command(label="Run", accelerator="Ctrl+Enter", command=self.run)
        m.add_command(label="Stop", accelerator="Esc", command=self.stop)
        m.add_separator()
        m.add_command(label="Use result as input", accelerator="Ctrl+U",
                      command=self.use_result)
        m.add_command(label="Copy result", command=self.copy_result)
        m.add_command(label="Clear output", accelerator="Ctrl+L", command=self.clear_output)

        m = menu("View")
        self._theme_var = tk.StringVar(value=self.theme.name)
        m.add_radiobutton(label="Dark", value="dark", variable=self._theme_var,
                          command=lambda: self.set_theme("dark"))
        m.add_radiobutton(label="Light", value="light", variable=self._theme_var,
                          command=lambda: self.set_theme("light"))
        m.add_separator()
        self._inspector_var = tk.BooleanVar(value=bool(self.prefs["inspector"]))
        m.add_checkbutton(label="Inspector", variable=self._inspector_var,
                          command=self._toggle_inspector)
        m.add_separator()
        m.add_command(label="Find a command", accelerator="Ctrl+K",
                      command=self.focus_search)

        m = menu("Help")
        m.add_command(label="Field guide for this command", accelerator="F1",
                      command=self.open_manual)
        m.add_command(label="Getting started",
                      command=lambda: self.show_manual("getting-started"))
        m.add_command(label="Capabilities", command=lambda: self.run_argv(["version"]))
        m.add_separator()
        m.add_command(label="About AESOP", command=self.about)
        self.root.configure(menu=self.menubar)

    def _build_layout(self) -> None:
        root = self.root
        self.status = ttk.Frame(root, padding=(12, 4))
        self.status.pack(side="bottom", fill="x")
        ttk.Separator(root).pack(side="bottom", fill="x")
        self.status_text = ttk.Label(self.status, text="", style="Status.TLabel")
        self.status_text.pack(side="left")
        self.worker_text = ttk.Label(self.status, text="", style="Status.TLabel")
        self.worker_text.pack(side="right")

        self.body = ttk.Panedwindow(root, orient="horizontal")
        self.body.pack(fill="both", expand=True)

        # -- sidebar -------------------------------------------------------- #
        side = ttk.Frame(self.body, padding=(12, 12, 6, 8))
        brand = ttk.Frame(side)
        brand.pack(fill="x", pady=(0, 10))
        self.brand = ttk.Label(brand, text="AESOP", font=self.theme.fonts["title"])
        self.brand.pack(side="left")
        ttk.Label(brand, text=f"workbench {__version__}", style="Small.TLabel") \
            .pack(side="left", padx=8, pady=(6, 0))
        self.search = PlaceholderEntry(side, self.theme, "Find a command   Ctrl+K")
        self.search.pack(fill="x")
        self.search.var.trace_add("write", lambda *_a: self._fill_tree())
        self.search.bind("<Return>", lambda _e: self._pick_first())
        self.search.bind("<Down>", lambda _e: self.tree.focus_set())
        holder = ttk.Frame(side)
        holder.pack(fill="both", expand=True, pady=(8, 0))
        self.tree = ttk.Treeview(holder, show="tree", selectmode="browse")
        self.tree.column("#0", width=200, stretch=True)
        self.tree.pack(side="left", fill="both", expand=True)
        autoscroll(self.tree, ttk.Scrollbar(holder, orient="vertical"),
                   side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.body.add(side, weight=0)

        # -- tabs ----------------------------------------------------------- #
        self.tabs = ttk.Notebook(self.body)
        self.body.add(self.tabs, weight=1)
        self.workbench = ttk.Frame(self.tabs)
        self.tabs.add(self.workbench, text="Workbench")
        self.manual = ManualView(self.tabs, self.theme, self.resolve_code)
        self.tabs.add(self.manual, text="Field guide")
        self.history = HistoryView(self.tabs, self.theme, self.restore, self.rerun)
        self.tabs.add(self.history, text="History")
        self.tabs.bind("<<NotebookTabChanged>>", self._on_tab)

        self.split = ttk.Panedwindow(self.workbench, orient="horizontal")
        self.split.pack(fill="both", expand=True)
        self.centre = ttk.Panedwindow(self.split, orient="vertical")
        self.split.add(self.centre, weight=1)
        self.inspector = Inspector(self.split, self.theme, self.load_example)
        if self.prefs["inspector"]:
            self.split.add(self.inspector, weight=0)

        self._build_command_pane()
        self._build_output_pane()
        self.root.after(50, self._place_sashes)

    def _place_sashes(self) -> None:
        """Give the command pane a little over half the height to start with."""
        if self._closed:
            return
        self.root.update_idletasks()
        height = self.centre.winfo_height()
        if height > 200:
            self.centre.sashpos(0, int(height * 0.54))

    def _build_command_pane(self) -> None:
        pane = ttk.Frame(self.centre, padding=(16, 12, 12, 6))
        self.centre.add(pane, weight=1)

        head = ttk.Frame(pane)
        head.pack(fill="x")
        self.cmd_name = ttk.Label(head, text="", style="Title.TLabel")
        self.cmd_name.pack(side="left")
        self.cmd_alias = ttk.Label(head, text="", style="Muted.TLabel")
        self.cmd_alias.pack(side="left", padx=10, pady=(5, 0))
        self.manual_button = ttk.Button(head, text="Field guide  F1", style="Ghost.TButton",
                                        command=self.open_manual)
        self.manual_button.pack(side="right")
        self.cmd_summary = ttk.Label(pane, text="", style="Secondary.TLabel",
                                     justify="left", wraplength=700)
        self.cmd_summary.pack(fill="x", pady=(2, 8))
        pane.bind("<Configure>",
                  lambda e: self.cmd_summary.configure(wraplength=max(200, e.width - 40)))

        # action bar (packed first so it keeps its place when space is tight)
        actions = ttk.Frame(pane)
        actions.pack(side="bottom", fill="x", pady=(8, 0))
        self.run_button = ttk.Button(actions, text="Run   Ctrl+⏎", style="Accent.TButton",
                                     command=self.run)
        self.run_button.pack(side="right")
        self.stop_button = ttk.Button(actions, text="Stop", command=self.stop,
                                      state="disabled")
        self.stop_button.pack(side="right", padx=8)
        ttk.Button(actions, text="Copy", style="Ghost.TButton",
                   command=self.copy_command).pack(side="right", padx=(6, 8))
        self.cmdline = ttk.Label(actions, text="", style="Mono.TLabel", anchor="w")
        self.cmdline.pack(side="left", fill="x", expand=True)

        # -- input ---------------------------------------------------------- #
        self.input_box = ttk.Frame(pane)
        bar = ttk.Frame(self.input_box)
        bar.pack(fill="x")
        ttk.Label(bar, text="Input", style="Section.TLabel").pack(side="left")
        self.input_note = ttk.Label(bar, text="", style="Small.TLabel")
        self.input_note.pack(side="left", padx=10)
        ttk.Button(bar, text="Clear", style="Ghost.TButton",
                   command=lambda: self.set_input("")).pack(side="right")
        ttk.Button(bar, text="Paste", style="Ghost.TButton",
                   command=self.paste_input).pack(side="right")
        self.encoding = tk.StringVar(value="auto")
        self.encoding_box = ttk.Combobox(bar, textvariable=self.encoding, values=ENCODINGS,
                                         state="readonly", width=10)
        self.encoding_box.pack(side="right", padx=(4, 10))
        self.encoding_label = ttk.Label(bar, text="Decode as", style="Small.TLabel")
        self.encoding_label.pack(side="right")

        self.file_row = ttk.Frame(self.input_box)
        self.file_row.pack(side="bottom", fill="x", pady=(6, 0))
        ttk.Label(self.file_row, text="or file", style="Small.TLabel").pack(side="left")
        self.file = tk.StringVar()
        ttk.Entry(self.file_row, textvariable=self.file, font=self.theme.fonts["mono"]) \
            .pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(self.file_row, text="Browse…", style="Ghost.TButton",
                   command=self.open_file).pack(side="left")
        ttk.Button(self.file_row, text="✕", style="Ghost.TButton", width=2,
                   command=lambda: self.file.set("")).pack(side="left")

        self.input = tk.Text(self.input_box, height=6, wrap="word", undo=True,
                             font=self.theme.fonts["mono"], padx=10, pady=8)
        self.input.pack(fill="both", expand=True, pady=(6, 0))
        self.input.bind("<<Modified>>", self._on_input_modified)
        self.input.bind("<Control-a>", self._select_all_input)
        self.input.bind("<Control-A>", self._select_all_input)
        self.encoding.trace_add("write", lambda *_a: self._changed(inspect=True))
        self.file.trace_add("write", lambda *_a: self._changed(inspect=True))

        # -- options + examples --------------------------------------------- #
        self.scroll = ScrollFrame(pane, self.theme)
        body = self.scroll.body
        self.options_label = ttk.Label(body, text="Options", style="Section.TLabel")
        self.options_label.pack(anchor="w", pady=(10, 2))
        self.form = CommandForm(body, self.theme, self._changed)
        self.form.pack(fill="x")
        self.examples_label = ttk.Label(body, text="Examples — click to load",
                                        style="Section.TLabel")
        self.examples = ttk.Frame(body)

    def _build_output_pane(self) -> None:
        pane = ttk.Frame(self.centre, padding=(16, 6, 12, 10))
        self.centre.add(pane, weight=2)
        bar = ttk.Frame(pane)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, text="Output", style="Section.TLabel").pack(side="left")
        self.output_note = ttk.Label(bar, text="", style="Small.TLabel")
        self.output_note.pack(side="left", padx=10)
        for text, command in (("Clear", self.clear_output), ("Save…", self.save_output),
                              ("Copy all", self.copy_output)):
            ttk.Button(bar, text=text, style="Ghost.TButton", command=command) \
                .pack(side="right")
        self.use_button = ttk.Button(bar, text="Use result as input", style="Ghost.TButton",
                                     command=self.use_result, state="disabled")
        self.use_button.pack(side="right", padx=(0, 6))

        prompt = ttk.Frame(pane)
        prompt.pack(side="bottom", fill="x", pady=(8, 0))
        self.prompt_label = ttk.Label(prompt, text="aesop »", font=self.theme.fonts["mono_bold"])
        self.prompt_label.pack(side="left", padx=(0, 8))
        self.bar = PlaceholderEntry(prompt, self.theme,
                                    "or type any command, e.g.  vigenere -k LEMON --encode "
                                    "'Attack at dawn'", font=self.theme.fonts["mono"])
        self.bar.pack(side="left", fill="x", expand=True)
        self.bar.bind("<Return>", self._on_bar)
        self.bar.bind("<Up>", lambda _e: self._bar_recall(-1))
        self.bar.bind("<Down>", lambda _e: self._bar_recall(1))

        self.output_frame = ScrolledText(pane, self.theme)
        self.output_frame.pack(fill="both", expand=True)
        self.output = self.output_frame.text
        self.output.on_use = self.set_input
        self._welcome()

    def _bind_keys(self) -> None:
        r = self.root

        def key(seq: str, fn: Callable[[], Any]) -> None:
            def handler(_event: tk.Event) -> str:
                fn()
                return "break"
            r.bind_all(seq, handler)
            # tk.Text has class bindings for several of these; ours must win
            self.input.bind(seq, handler)

        key("<Control-Return>", self.run)
        key("<Control-KP_Enter>", self.run)
        key("<Control-k>", self.focus_search)
        key("<Control-l>", self.clear_output)
        key("<Control-o>", self.open_file)
        key("<Control-s>", self.save_output)
        key("<Control-q>", self.close)
        key("<Control-u>", self.use_result)
        key("<F1>", self.open_manual)
        r.bind_all("<Escape>", lambda _e: self.stop())

    def _apply_theme(self, p: Palette) -> None:
        self.theme.style_text(self.input)
        self.theme.style_combobox(self.encoding_box)
        for m in self.menus:
            self.theme.style_menu(m)
        self.brand.configure(foreground=p.accent_text)
        self.prompt_label.configure(foreground=p.accent_text)
        self.tree.tag_configure("group", foreground=p.muted, font=self.theme.fonts["small"])
        self._sync_input_state()

    # ======================================================================= #
    # Command list
    # ======================================================================= #
    def _fill_tree(self) -> None:
        term = self.search.value().strip().lower()
        if term == getattr(self, "_term", None):
            return                  # e.g. the placeholder text coming and going
        self._term = term
        self.tree.delete(*self.tree.get_children())
        self._visible: List[str] = []
        for gkey, cmds in commands_by_group().items():
            hits = [c for c in cmds if not term or term in c.name.lower()
                    or any(term in a.lower() for a in c.aliases)
                    or term in c.summary.lower()]
            if not hits:
                continue
            node = self.tree.insert("", "end", iid=f"group:{gkey}",
                                    text=GROUPS[gkey].upper(), open=True, tags=("group",))
            # exact and prefix name matches first when searching
            if term:
                hits.sort(key=lambda c: (c.name != term, not c.name.startswith(term), c.name))
            for c in hits:
                self.tree.insert(node, "end", iid=c.name, text=c.name)
                self._visible.append(c.name)
        if self.cmd is not None and self.tree.exists(self.cmd.name):
            self._loading = True
            self.tree.selection_set(self.cmd.name)
            self.tree.see(self.cmd.name)
            self.root.after_idle(self._end_loading)

    def _end_loading(self) -> None:
        self._loading = False

    def _pick_first(self) -> None:
        term = self.search.value().strip().lower()
        match = resolve(term)
        name = match.name if match else (self._visible[0] if self._visible else None)
        if name:
            self.select_command(name)
            self.focus_input()

    def _on_tree_select(self, _event: tk.Event) -> None:
        sel = self.tree.selection()
        if self._loading or not sel or sel[0].startswith("group:"):
            return
        if self.cmd is None or sel[0] != self.cmd.name:
            self.select_command(sel[0])
        self.tabs.select(self.workbench)

    def focus_search(self) -> None:
        self.search.focus_set()
        self.search.select_range(0, "end")

    def focus_input(self) -> None:
        if self._has("input"):
            self.input.focus_set()

    # ======================================================================= #
    # Showing a command
    # ======================================================================= #
    def _has(self, what: str) -> bool:
        """Does the current command take the shared input / file / encoding?"""
        if self.cmd is None:
            return False
        fields = forms.fields_for(self.cmd)
        takes_input = any(f.kind == forms.INPUT for f in fields)
        if what == "input":
            return takes_input
        dest = {"file": "file", "encoding": "in_encoding"}[what]
        return takes_input and any(f.dest == dest and not f.positional for f in fields)

    def _shared(self) -> List[str]:
        """Form fields handled by the input box rather than the options list."""
        out = []
        if self._has("input"):
            out += [f.dest for f in forms.fields_for(self.cmd) if f.kind == forms.INPUT]
        if self._has("file"):
            out.append("file")
        if self._has("encoding"):
            out.append("in_encoding")
        return out

    def select_command(self, name: str) -> bool:
        cmd = resolve(name)
        if cmd is None:
            return False
        self.cmd = cmd
        self.prefs["command"] = cmd.name
        self.cmd_name.configure(text=cmd.name)
        self.cmd_alias.configure(
            text=("also: " + ", ".join(cmd.aliases)) if cmd.aliases else "")
        self.cmd_summary.configure(text=cmd.summary)
        has_page = bool(cmd.manual and get_page(cmd.manual))
        self.manual_button.configure(state="normal" if has_page else "disabled")

        # input box, only for commands that take data
        self.scroll.pack_forget()
        self.input_box.pack_forget()
        if self._has("input"):
            self.input_box.pack(fill="x")
            for w in (self.encoding_box, self.encoding_label):
                w.pack_forget()
            if self._has("encoding"):
                self.encoding_box.pack(side="right", padx=(4, 10))
                self.encoding_label.pack(side="right")
            if self._has("file"):
                self.file_row.pack(side="bottom", fill="x", pady=(6, 0), before=self.input)
            else:
                self.file_row.pack_forget()
        self.scroll.pack(fill="both", expand=True)

        self.form.build(cmd, skip=self._shared())
        self._fill_examples(cmd)
        self.scroll.refresh()
        self._sync_input_state()
        self._changed()

        if self.tree.exists(cmd.name) and self.tree.selection() != (cmd.name,):
            self._loading = True
            self.tree.selection_set(cmd.name)
            self.tree.see(cmd.name)
            self.root.after_idle(self._end_loading)
        return True

    def _fill_examples(self, cmd: Command) -> None:
        for child in self.examples.winfo_children():
            child.destroy()
        self.examples_label.pack_forget()
        self.examples.pack_forget()
        if not cmd.examples:
            return
        self.examples_label.pack(anchor="w", pady=(14, 2))
        self.examples.pack(fill="x")
        for ex in cmd.examples:
            usable = self._example_target(ex) is not None
            lab = ttk.Label(self.examples, text=ex, font=self.theme.fonts["mono_small"],
                            style="Link.TLabel" if usable else "Muted.TLabel",
                            cursor="hand2" if usable else "")
            lab.pack(anchor="w", pady=1)
            if usable:
                lab.bind("<Button-1>", lambda _e, s=ex: self.load_example(s))

    # ======================================================================= #
    # Input & form state
    # ======================================================================= #
    def get_input(self) -> str:
        return self.input.get("1.0", "end-1c")

    def set_input(self, text: str) -> None:
        """Replace the input (undoable) and point the form at it, not a file."""
        self.input.configure(state="normal")
        self.input.delete("1.0", "end")
        self.input.insert("1.0", text)
        if self.file.get():
            self.file.set("")
        self._changed(inspect=True)
        self.tabs.select(self.workbench)

    def paste_input(self) -> None:
        try:
            self.set_input(self.root.clipboard_get())
        except tk.TclError:
            self.set_status("The clipboard is empty.", bad=True)

    def _select_all_input(self, _event: tk.Event) -> str:
        self.input.tag_add("sel", "1.0", "end-1c")
        return "break"

    def _on_input_modified(self, _event: tk.Event) -> None:
        if self.input.edit_modified():
            self.input.edit_modified(False)
            self._changed(inspect=True)

    def _sync_input_state(self) -> None:
        """Dim the text box while a file is selected (the file wins, as on the CLI)."""
        p = self.theme.palette
        from_file = bool(self.file.get().strip()) and self._has("file")
        self.input.configure(foreground=p.muted if from_file else p.text)
        self.input_note.configure(
            text="reading from the file below — the text is ignored" if from_file else "")

    def values(self) -> Dict[str, Any]:
        """The complete form state for the current command."""
        vals = self.form.values()
        if self._has("input"):
            from_file = self._has("file") and self.file.get().strip()
            for f in forms.fields_for(self.cmd):
                if f.kind == forms.INPUT:
                    vals[f.dest] = "" if from_file else self.get_input()
            if self._has("file"):
                vals["file"] = self.file.get().strip()
            if self._has("encoding"):
                vals["in_encoding"] = self.encoding.get()
        return vals

    def set_values(self, values: Dict[str, Any]) -> None:
        self.form.set_values(values)
        if self._has("input"):
            for f in forms.fields_for(self.cmd):
                if f.kind == forms.INPUT and values.get(f.dest):
                    self.input.delete("1.0", "end")
                    self.input.insert("1.0", str(values[f.dest]))
            if self._has("file"):
                self.file.set(str(values.get("file") or ""))
            if self._has("encoding"):
                self.encoding.set(str(values.get("in_encoding") or "auto"))
        self._changed(inspect=True)

    def argv(self) -> List[str]:
        return forms.build_argv(self.cmd, self.values()) if self.cmd else []

    def _changed(self, inspect: bool = False) -> None:
        self._sync_input_state()
        self._debounce("cmdline", 80, self._update_cmdline)
        if inspect:
            self._debounce("inspect", 300, self.refresh_inspector)

    def _debounce(self, key: str, ms: int, fn: Callable[[], None]) -> None:
        if self._closed:
            return
        if key in self._after:
            self.root.after_cancel(self._after[key])

        def fire() -> None:
            self._after.pop(key, None)
            if not self._closed:
                fn()
        self._after[key] = self.root.after(ms, fire)

    def _update_cmdline(self) -> None:
        self.cmdline.configure(text="$ " + forms.command_line(self.argv(), max_arg=48))

    def refresh_inspector(self) -> None:
        path = self.file.get().strip()
        if path and not os.path.isfile(path):
            path = ""
        self.inspector.show(analyse(self.get_input(), encoding=self.encoding.get(),
                                    file=path or None))

    # ======================================================================= #
    # Examples, manual links
    # ======================================================================= #
    def _example_target(self, line: str):
        parsed = forms.parse_example(line)
        if parsed is None:
            return None
        cmd = resolve(parsed[0])
        if cmd is None:
            return None
        try:
            values = forms.values_from_argv(cmd, parsed[1])
        except forms.FormError:
            return None
        if parsed[2] is not None:
            for f in forms.fields_for(cmd):
                if f.kind == forms.INPUT:
                    values[f.dest] = parsed[2]
        return cmd, values

    def load_example(self, line: str) -> bool:
        """Put a documented example into the form, ready to run."""
        target = self._example_target(line)
        if target is None:
            return False
        cmd, values = target
        self.select_command(cmd.name)
        if self._has("input"):
            own_input = bool(values.get("file")) or any(
                values.get(f.dest) for f in forms.fields_for(cmd) if f.kind == forms.INPUT)
            if own_input:                       # the example brings its own data
                values.setdefault("file", "")
                values.setdefault("in_encoding", "auto")
            else:                               # keep whatever is in the workspace
                values["file"] = self.file.get()
                values.setdefault("in_encoding", self.encoding.get())
        self.set_values(values)
        self.tabs.select(self.workbench)
        self.set_status(f"Loaded example for {cmd.name} — press Run.")
        return True

    def resolve_code(self, code: str) -> Optional[Callable[[], None]]:
        """What clicking a piece of manual text should do, if anything."""
        code = code.strip()
        if code.startswith("$ "):
            code = code[2:].strip()
        if re.match(r"^https?://", code):
            return lambda: webbrowser.open(code)
        m = _MANUAL_REF.match(code.split("#")[0].strip())
        if m:
            slug = m.group(1)
            return (lambda: self.show_manual(slug)) if get_page(slug) else None
        if code.endswith(".md") and get_page(os.path.basename(code)[:-3]):
            return lambda: self.show_manual(os.path.basename(code)[:-3])
        if self._example_target(code) is not None:
            return lambda: self.load_example(code)
        return None

    def show_manual(self, slug: str) -> None:
        if self.manual.show(slug):
            self.tabs.select(self.manual)

    def open_manual(self) -> None:
        if self.cmd is not None and self.cmd.manual:
            self.show_manual(self.cmd.manual)

    def _on_tab(self, _event: tk.Event) -> None:
        if self.tabs.select() == str(self.manual) and self.manual.slug is None:
            slug = self.cmd.manual if self.cmd and self.cmd.manual else "getting-started"
            if not self.manual.show(slug):
                self.manual.show("getting-started")

    # ======================================================================= #
    # Running
    # ======================================================================= #
    def run(self) -> None:
        if self.cmd is None or self.runner.busy:
            return
        values = self.values()
        missing = forms.missing_required(self.cmd, values)
        if missing:
            self.set_status("Fill in " + ", ".join(f.label for f in missing) + " first.",
                            bad=True)
            return
        self.run_argv(forms.build_argv(self.cmd, values), values=values)

    def run_argv(self, argv: List[str], values: Optional[Dict[str, Any]] = None) -> None:
        if self.runner.busy or not argv:
            return
        cmd = resolve(argv[0])
        record = Run(argv=list(argv), command=cmd.name if cmd else "", values=values)
        try:
            self._run_id = self.runner.submit(argv)
        except RuntimeError as exc:
            self.set_status(str(exc), bad=True)
            return
        self.run_record = self.shown = record
        self.output.clear()
        self.output.put("$ " + forms.command_line(argv, max_arg=400) + "\n", "cmdline")
        self.tabs.select(self.workbench)
        self.set_status(f"Running {argv[0]}…")
        self._sync_run_state()

    def stop(self) -> None:
        if self.runner.busy:
            self.set_status("Stopping…")
            self.runner.cancel()

    def rerun(self, run: Run) -> None:
        self.run_argv(run.argv, values=run.values)

    def restore(self, run: Run) -> None:
        """Bring a past run back: its form state and its output."""
        if run.command and self.select_command(run.command):
            values = run.values
            if values is None:
                try:
                    values = forms.values_from_argv(self.cmd, run.argv[1:])
                except forms.FormError:
                    values = None
            if values is not None:
                self.set_values(values)
        self.show_run(run)
        self.tabs.select(self.workbench)

    def show_run(self, run: Run) -> None:
        self.shown = run
        self.output.clear()
        self.output.put("$ " + forms.command_line(run.argv, max_arg=400) + "\n", "cmdline")
        for ev in run.events:
            self.output.add_event(ev)
        self._footer(run)
        self.output.yview_moveto(0)
        self._sync_run_state()

    def _footer(self, run: Run) -> None:
        self.output._fresh_line()
        tag = "muted" if run.code == 0 or run.cancelled else "bad"
        self.output.put(f"{run.outcome} · {format_elapsed(run.elapsed)}\n", "status", tag)

    def _sync_run_state(self) -> None:
        busy = self.runner.busy
        self.run_button.configure(state="disabled" if busy else "normal")
        self.stop_button.configure(state="normal" if busy else "disabled")
        has_result = bool(self.shown and self.shown.result is not None) and not busy
        self.use_button.configure(state="normal" if has_result else "disabled")

    def _poll(self) -> None:
        if self._closed:
            return
        try:
            for _ in range(200):
                self._handle(self.events.get_nowait())
        except queue.Empty:
            pass
        self.root.after(POLL_MS, self._poll)

    def _handle(self, ev: Dict[str, Any]) -> None:
        kind = ev.get("kind")
        if kind == "ready":
            errors = ev.get("load_errors") or []
            self.worker_text.configure(
                text=f"{ev.get('commands', len(REGISTRY))} commands · worker ready"
                + (f" · {len(errors)} modules failed to load" if errors else ""))
            if not self.runner.busy and self.status_text.cget("text").startswith("Starting"):
                self.set_status("Ready.")
            return
        run = self.run_record
        if run is None or ev.get("id") != self._run_id or kind == "start":
            return
        if kind == "done":
            run.code = ev.get("code", 0)
            run.cancelled = bool(ev.get("cancelled"))
            run.elapsed = float(ev.get("elapsed") or (time.time() - run.started))
            self.run_record = None
            self._footer(run)
            self.history.add(run)
            self._sync_run_state()
            self.set_status(f"{run.argv[0]}: {run.outcome} in {format_elapsed(run.elapsed)}",
                            bad=bool(run.code) and not run.cancelled)
            return
        run.events.append(ev)
        if self.shown is run:
            self.output.add_event(ev)

    # -- the command bar ---------------------------------------------------- #
    def _on_bar(self, _event: tk.Event) -> str:
        line = self.bar.value().strip()
        if not line or self.runner.busy:
            return "break"
        try:
            argv = shlex.split(line, comments=False)
        except ValueError as exc:
            self.set_status(f"Cannot parse that: {exc}", bad=True)
            return "break"
        if argv and argv[0] == "aesop":
            argv = argv[1:]
        if not argv:
            return "break"
        self._bar_history.append(line)
        self._bar_pos = len(self._bar_history)
        self.bar.set_value("")
        if argv[0] in ("manual", "man") and len(argv) == 2 and get_page(argv[1]):
            self.show_manual(argv[1])
            return "break"
        self.run_argv(argv)
        return "break"

    def _bar_recall(self, step: int) -> str:
        if self._bar_history:
            self._bar_pos = max(0, min(len(self._bar_history), self._bar_pos + step))
            self.bar.set_value(self._bar_history[self._bar_pos]
                               if self._bar_pos < len(self._bar_history) else "")
            self.bar.icursor("end")
        return "break"

    # ======================================================================= #
    # Output actions
    # ======================================================================= #
    def _welcome(self) -> None:
        o = self.output
        o.put(cli.BANNER.strip("\n") + "\n\n", "mono", "link")
        o.put("Pick a command on the left, put your data in the input box, and press ", "para")
        o.put("Run", "md_bold")
        o.put(". Not sure what you are looking at? Start with ", "para")
        o.link("auto", lambda: self.select_command("auto"), "md_code")
        o.put(" or ", "para")
        o.link("identify", lambda: self.select_command("identify"), "md_code")
        o.put(".\n", "para")
        o.put("Results can be sent straight back into the input — right-click any table "
              "cell, or use the links under a result — so multi-step solves stay in one "
              "place.\n", "para", "muted")

    def clear_output(self) -> None:
        self.output.clear()
        self.shown = None
        self._sync_run_state()

    def output_text(self) -> str:
        if self.shown is None:
            return ""
        return "$ " + forms.command_line(self.shown.argv) + "\n" + events_to_text(self.shown.events)

    def copy_output(self) -> None:
        text = self.output_text()
        if text:
            self.output.copy(text)
            self.set_status("Output copied.")

    def copy_result(self) -> None:
        if self.shown is not None and self.shown.result is not None:
            self.output.copy(self.shown.result)
            self.set_status("Result copied.")

    def copy_command(self) -> None:
        self.output.copy(forms.command_line(self.argv()))
        self.set_status("Command line copied.")

    def use_result(self) -> None:
        if self.shown is not None and self.shown.result is not None and not self.runner.busy:
            self.set_input(self.shown.result.rstrip("\n"))
            self.set_status("Result moved to the input.")

    def save_output(self) -> None:
        text = self.output_text()
        if not text:
            self.set_status("There is no output to save yet.", bad=True)
            return
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Save output", defaultextension=".txt",
            initialfile=f"aesop-{self.shown.argv[0]}.txt",
            filetypes=[("Text", "*.txt"), ("All files", "*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            messagebox.showerror("Save output", str(exc), parent=self.root)
            return
        self.set_status(f"Saved {path}")

    def open_file(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title="Open input file")
        if not path:
            return
        if self._has("file"):
            self.file.set(path)
            return
        for f in forms.fields_for(self.cmd) if self.cmd else []:
            if f.kind == forms.PATH:                 # e.g. pcap's capture
                self.form.set_values({**self.form.values(), f.dest: path})
                return
        self.set_status("This command does not read a file.", bad=True)

    # ======================================================================= #
    # Window
    # ======================================================================= #
    def set_status(self, text: str, bad: bool = False) -> None:
        self.status_text.configure(text=text, style="Bad.TLabel" if bad else "Status.TLabel")

    def set_theme(self, name: str) -> None:
        self.prefs["theme"] = name
        self._theme_var.set(name)
        self.theme.set(name)

    def _toggle_inspector(self) -> None:
        show = bool(self._inspector_var.get())
        self.prefs["inspector"] = show
        shown = str(self.inspector) in self.split.panes()
        if show and not shown:
            self.split.add(self.inspector, weight=0)
            self.refresh_inspector()
        elif not show and shown:
            self.split.forget(self.inspector)

    def about(self) -> None:
        messagebox.showinfo(
            "About AESOP",
            f"AESOP {__version__}\nAnalytic Encryption-Solving Oracle Platform\n\n"
            "A cryptanalysis workbench for CTF, research and teaching.\n"
            "Use it on data and systems you own or are authorised to assess.\n\n"
            "Apache-2.0",
            parent=self.root)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for handle in self._after.values():
            try:
                self.root.after_cancel(handle)
            except tk.TclError:
                pass
        try:
            if self.root.state() == "normal":
                self.prefs["geometry"] = self.root.geometry()
        except tk.TclError:
            pass
        self.prefs.save()
        self.runner.close()
        self.root.destroy()

"""
aesop.gui.theme — colours, fonts and ttk styling for the workbench.

One :class:`Palette` per mode; every widget reads colours by *role* (surface,
muted, accent…) so switching between dark and light is a single call.  The
brand accent is the fox's amber from :mod:`aesop.ui`; chart colours follow a
separate, colour-blind-checked data palette and never reuse the accent.
"""
from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from tkinter import font as tkfont
from tkinter import ttk
from typing import Callable, Dict, List


@dataclass(frozen=True)
class Palette:
    name: str
    bg: str                 # window / page plane
    surface: str            # editors, output, cards
    raised: str             # buttons, hover, code blocks
    border: str
    text: str
    secondary: str
    muted: str
    accent: str             # filled accent (buttons, selection marker)
    accent_hover: str
    accent_text: str        # accent used *as text* on surface
    on_accent: str          # text on a filled accent
    select: str             # selection background
    good: str
    warn: str
    bad: str
    info: str
    magenta: str
    # charts
    chart_grid: str
    chart_axis: str
    series: str             # the data series
    series_wash: str        # area under a line (series at ~10% on surface)
    series_dim: str         # non-hovered bars while hovering
    reference: str          # reference marks (expected values)


DARK = Palette(
    name="dark",
    bg="#121211", surface="#1a1a19", raised="#262624", border="#383835",
    text="#f4f3ee", secondary="#c3c2b7", muted="#898781",
    accent="#d97706", accent_hover="#f08c1a", accent_text="#f2a33c", on_accent="#140b00",
    select="#3a2a12",
    good="#3fbf3f", warn="#fab219", bad="#f07f7f", info="#5cb8e6", magenta="#e07aa6",
    chart_grid="#2c2c2a", chart_axis="#383835",
    series="#3987e5", series_wash="#1d2530", series_dim="#234a7a", reference="#c3c2b7",
)

LIGHT = Palette(
    name="light",
    bg="#f4f3ef", surface="#fcfcfb", raised="#ecebe6", border="#d6d5cd",
    text="#0b0b0b", secondary="#52514e", muted="#6b6963",
    accent="#d97706", accent_hover="#b86405", accent_text="#a85504", on_accent="#ffffff",
    select="#fbe3c2",
    good="#006300", warn="#8a5a00", bad="#b52f2f", info="#1c5cab", magenta="#a83a6c",
    chart_grid="#e1e0d9", chart_axis="#c3c2b7",
    series="#2a78d6", series_wash="#e7f0fb", series_dim="#a9c8ee", reference="#52514e",
)

PALETTES: Dict[str, Palette] = {"dark": DARK, "light": LIGHT}

_SANS = ("Inter", "Ubuntu", "Noto Sans", "Segoe UI", "Helvetica Neue", "DejaVu Sans")
_MONO = ("JetBrains Mono", "DejaVu Sans Mono", "Ubuntu Mono", "Noto Sans Mono",
         "Menlo", "Consolas", "Liberation Mono")


def _pick(root: tk.Misc, wanted, fallback: str) -> str:
    have = set(tkfont.families(root))
    for fam in wanted:
        if fam in have:
            return fam
    return tkfont.nametofont(fallback).actual("family")


class Theme:
    """Holds the active palette and the named fonts; restyles on change."""

    def __init__(self, root: tk.Misc, name: str = "dark"):
        self.root = root
        self.palette = PALETTES.get(name, DARK)
        self._listeners: List[Callable[[Palette], None]] = []
        sans = _pick(root, _SANS, "TkDefaultFont")
        mono = _pick(root, _MONO, "TkFixedFont")
        F = tkfont.Font
        self.fonts = {
            "ui": F(root, family=sans, size=10),
            "ui_bold": F(root, family=sans, size=10, weight="bold"),
            "ui_italic": F(root, family=sans, size=10, slant="italic"),
            "small": F(root, family=sans, size=9),
            "title": F(root, family=sans, size=15, weight="bold"),
            "h1": F(root, family=sans, size=17, weight="bold"),
            "h2": F(root, family=sans, size=13, weight="bold"),
            "h3": F(root, family=sans, size=11, weight="bold"),
            "stat": F(root, family=sans, size=14, weight="bold"),
            "mono": F(root, family=mono, size=10),
            "mono_bold": F(root, family=mono, size=10, weight="bold"),
            "mono_italic": F(root, family=mono, size=10, slant="italic"),
            "mono_small": F(root, family=mono, size=9),
        }
        self.style = ttk.Style(root)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.apply()

    # -- public ------------------------------------------------------------- #
    @property
    def name(self) -> str:
        return self.palette.name

    def listen(self, fn: Callable[[Palette], None]) -> None:
        """Call ``fn(palette)`` now and whenever the theme changes."""
        self._listeners.append(fn)
        fn(self.palette)

    def set(self, name: str) -> None:
        self.palette = PALETTES.get(name, DARK)
        self.apply()
        for fn in list(self._listeners):
            fn(self.palette)

    def colour(self, name: str) -> str:
        """Resolve a console colour name (``green``, ``#d97706``…) for this mode."""
        p = self.palette
        name = name.replace("bright_", "")
        table = {"green": p.good, "red": p.bad, "yellow": p.warn, "cyan": p.info,
                 "blue": p.series, "magenta": p.magenta, "white": p.text,
                 "black": p.muted, "grey": p.muted, "gray": p.muted, "default": p.text}
        if name.lower() == "#d97706":
            return p.accent_text
        return table.get(name, name)

    # -- ttk ---------------------------------------------------------------- #
    def apply(self) -> None:
        p, f, s = self.palette, self.fonts, self.style
        self.root.configure(background=p.bg)

        s.configure(".", background=p.bg, foreground=p.text, font=f["ui"],
                    bordercolor=p.border, lightcolor=p.bg, darkcolor=p.bg,
                    troughcolor=p.bg, focuscolor=p.accent,
                    selectbackground=p.select, selectforeground=p.text,
                    insertcolor=p.text, fieldbackground=p.surface)

        s.configure("TFrame", background=p.bg)
        s.configure("Surface.TFrame", background=p.surface)
        s.configure("Card.TFrame", background=p.surface, bordercolor=p.border,
                    lightcolor=p.border, darkcolor=p.border, borderwidth=1, relief="solid")
        s.configure("TLabel", background=p.bg, foreground=p.text)
        s.configure("Muted.TLabel", foreground=p.muted)
        s.configure("Small.TLabel", foreground=p.muted, font=f["small"])
        s.configure("Secondary.TLabel", foreground=p.secondary)
        s.configure("Title.TLabel", font=f["title"])
        s.configure("Section.TLabel", font=f["ui_bold"], foreground=p.secondary)
        s.configure("Mono.TLabel", font=f["mono"], foreground=p.secondary)
        s.configure("Flag.TLabel", font=f["mono"], foreground=p.info)
        s.configure("Stat.TLabel", font=f["stat"])
        s.configure("Bad.TLabel", foreground=p.bad)
        s.configure("Link.TLabel", foreground=p.accent_text)
        s.configure("Status.TLabel", foreground=p.secondary, font=f["small"])

        s.configure("TButton", background=p.raised, foreground=p.text, borderwidth=1,
                    bordercolor=p.border, lightcolor=p.raised, darkcolor=p.raised,
                    padding=(10, 4), relief="flat", focusthickness=1)
        s.map("TButton",
              background=[("disabled", p.bg), ("pressed", p.border), ("active", p.border)],
              lightcolor=[("disabled", p.bg), ("active", p.border)],
              darkcolor=[("disabled", p.bg), ("active", p.border)],
              foreground=[("disabled", p.muted)])
        s.configure("Accent.TButton", background=p.accent, foreground=p.on_accent,
                    bordercolor=p.accent, lightcolor=p.accent, darkcolor=p.accent,
                    font=f["ui_bold"], padding=(14, 4))
        s.map("Accent.TButton",
              background=[("disabled", p.raised), ("pressed", p.accent), ("active", p.accent_hover)],
              lightcolor=[("disabled", p.raised), ("active", p.accent_hover)],
              darkcolor=[("disabled", p.raised), ("active", p.accent_hover)],
              bordercolor=[("disabled", p.border), ("active", p.accent_hover)],
              foreground=[("disabled", p.muted)])
        s.configure("Ghost.TButton", background=p.bg, borderwidth=0, padding=(6, 2),
                    lightcolor=p.bg, darkcolor=p.bg, bordercolor=p.bg,
                    foreground=p.secondary, font=f["small"])
        s.map("Ghost.TButton",
              background=[("active", p.raised)], lightcolor=[("active", p.raised)],
              darkcolor=[("active", p.raised)], bordercolor=[("active", p.raised)],
              foreground=[("disabled", p.muted), ("active", p.text)])

        for name in ("TEntry", "TCombobox", "TSpinbox"):
            s.configure(name, fieldbackground=p.surface, foreground=p.text,
                        background=p.raised, arrowcolor=p.secondary,
                        bordercolor=p.border, lightcolor=p.surface, darkcolor=p.surface,
                        insertcolor=p.text, padding=(6, 3),
                        selectbackground=p.select, selectforeground=p.text)
            s.map(name,
                  bordercolor=[("focus", p.accent)],
                  lightcolor=[("focus", p.surface)],
                  darkcolor=[("focus", p.surface)],
                  fieldbackground=[("disabled", p.bg), ("readonly", p.surface)],
                  foreground=[("disabled", p.muted)],
                  selectbackground=[("readonly", p.surface)],
                  selectforeground=[("readonly", p.text)],
                  background=[("active", p.border)])
        s.configure("Mono.TEntry", font=f["mono"])
        # the combobox drop-down is a classic Tk listbox
        for opt, val in (("background", p.surface), ("foreground", p.text),
                         ("selectBackground", p.select), ("selectForeground", p.text),
                         ("font", f["ui"])):
            self.root.option_add(f"*TCombobox*Listbox.{opt}", val)

        s.configure("TCheckbutton", background=p.bg, foreground=p.text,
                    indicatorbackground=p.surface, indicatorforeground=p.on_accent,
                    upperbordercolor=p.border, lowerbordercolor=p.border,
                    indicatormargin=(0, 0, 8, 0), padding=(0, 2))
        s.map("TCheckbutton",
              background=[("active", p.bg)],
              indicatorbackground=[("selected", p.accent), ("active", p.raised)],
              upperbordercolor=[("selected", p.accent)],
              lowerbordercolor=[("selected", p.accent)],
              foreground=[("disabled", p.muted)])

        s.configure("Treeview", background=p.bg, fieldbackground=p.bg, foreground=p.text,
                    borderwidth=0, rowheight=int(f["ui"].metrics("linespace") * 1.7),
                    font=f["ui"])
        s.map("Treeview", background=[("selected", p.select)],
              foreground=[("selected", p.text)])
        s.configure("Treeview.Heading", background=p.bg, foreground=p.muted,
                    font=f["small"], borderwidth=0, relief="flat", padding=(6, 4))
        s.map("Treeview.Heading", background=[("active", p.raised)])
        s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])   # no border
        s.configure("Mono.Treeview", font=f["mono"])

        s.configure("TNotebook", background=p.bg, borderwidth=0, tabmargins=(8, 6, 8, 0))
        s.configure("TNotebook.Tab", background=p.bg, foreground=p.muted,
                    padding=(14, 6), borderwidth=0, font=f["ui_bold"],
                    lightcolor=p.bg, bordercolor=p.bg)
        s.map("TNotebook.Tab",
              background=[("selected", p.surface), ("active", p.raised)],
              foreground=[("selected", p.text), ("active", p.text)],
              lightcolor=[("selected", p.accent)],
              bordercolor=[("selected", p.border)],
              padding=[("selected", (14, 6))])

        # slim, arrowless scrollbars: just a thumb in a trough
        for orient, sticky in (("Vertical", "ns"), ("Horizontal", "ew")):
            s.layout(f"{orient}.TScrollbar", [(f"{orient}.Scrollbar.trough", {
                "sticky": sticky,
                "children": [(f"{orient}.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})],
            })])
        s.configure("TScrollbar", background=p.border, troughcolor=p.bg, borderwidth=0,
                    bordercolor=p.bg, lightcolor=p.border, darkcolor=p.border,
                    gripcount=0, width=10, arrowsize=10)
        s.map("TScrollbar", background=[("active", p.muted), ("disabled", p.bg)],
              lightcolor=[("active", p.muted), ("disabled", p.bg)],
              darkcolor=[("active", p.muted), ("disabled", p.bg)])
        s.configure("Surface.Vertical.TScrollbar", troughcolor=p.surface, bordercolor=p.surface)
        s.configure("Surface.Horizontal.TScrollbar", troughcolor=p.surface, bordercolor=p.surface)

        s.configure("TPanedwindow", background=p.bg)
        s.configure("Sash", sashthickness=7, gripcount=0, background=p.bg)
        s.configure("TSeparator", background=p.border)

    # -- classic Tk widgets ------------------------------------------------- #
    def style_text(self, widget: tk.Text, surface: bool = True) -> None:
        p = self.palette
        widget.configure(
            background=p.surface if surface else p.bg, foreground=p.text,
            insertbackground=p.text, selectbackground=p.select,
            selectforeground=p.text, inactiveselectbackground=p.select,
            highlightthickness=1, highlightbackground=p.border,
            highlightcolor=p.accent, borderwidth=0, relief="flat",
        )

    def style_combobox(self, box: ttk.Combobox) -> None:
        """Recolour the drop-down list of a combobox that outlives a theme change."""
        p = self.palette
        try:
            popdown = self.root.tk.call("ttk::combobox::PopdownWindow", str(box))
            self.root.tk.call(f"{popdown}.f.l", "configure",
                              "-background", p.surface, "-foreground", p.text,
                              "-selectbackground", p.select, "-selectforeground", p.text)
        except tk.TclError:
            pass

    def style_menu(self, menu: tk.Menu) -> None:
        p = self.palette
        menu.configure(background=p.surface, foreground=p.text,
                       activebackground=p.select, activeforeground=p.text,
                       disabledforeground=p.muted, borderwidth=0,
                       activeborderwidth=0, relief="flat", font=self.fonts["ui"],
                       selectcolor=p.accent_text)

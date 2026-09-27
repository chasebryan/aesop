"""
aesop.gui.charts — the inspector's three small charts, drawn on a Tk canvas.

* :class:`LetterChart`  — observed letter frequencies against English.
* :class:`ByteChart`    — distribution of byte values 0x00–0xFF.
* :class:`EntropyChart` — Shannon entropy along the data.

Each has one data series in the data colour; reference values are neutral
marks of a different shape, so nothing depends on telling two hues apart.
Axes and grid stay recessive, and hovering reads out exact values.
"""
from __future__ import annotations

import math
import tkinter as tk
from typing import Dict, List, Optional, Sequence, Tuple

from .theme import Palette, Theme

LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def nice_ceiling(value: float) -> float:
    """Round ``value`` up to 1, 2 or 5 × a power of ten (a clean axis maximum)."""
    if value <= 0:
        return 1.0
    exp = math.floor(math.log10(value))
    base = 10 ** exp
    for m in (1, 2, 5, 10):
        if value <= m * base:
            return m * base
    return 10 * base


class Chart(tk.Canvas):
    LEFT, RIGHT, TOP, BOTTOM = 38, 10, 30, 20

    title = ""

    def __init__(self, master: tk.Misc, theme: Theme, height: int = 150,
                 surface: str = "bg"):
        super().__init__(master, height=height, width=260, highlightthickness=0,
                         borderwidth=0)
        self.theme = theme
        self._surface = surface         # palette role the chart sits on
        self._hovered: Optional[int] = None
        self.bind("<Configure>", lambda _e: self.redraw())
        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", lambda _e: self._set_hover(None))
        theme.listen(self._apply_theme)

    # -- plumbing ----------------------------------------------------------- #
    @property
    def p(self) -> Palette:
        return self.theme.palette

    @property
    def surface(self) -> str:
        return getattr(self.p, self._surface)

    def _apply_theme(self, p: Palette) -> None:
        self.configure(background=self.surface)
        self.redraw()

    def plot(self) -> Tuple[int, int, int, int]:
        """(x0, y0, x1, y1) of the plotting area."""
        w = max(self.winfo_width(), 120)
        h = max(self.winfo_height(), 80)
        return self.LEFT, self.TOP, w - self.RIGHT, h - self.BOTTOM

    def has_data(self) -> bool:
        raise NotImplementedError

    def draw(self) -> None:
        raise NotImplementedError

    def index_at(self, x: int) -> Optional[int]:
        raise NotImplementedError

    def draw_hover(self, i: int) -> str:
        """Draw hover marks (tagged ``hover``); return the read-out text."""
        raise NotImplementedError

    def legend(self) -> None:
        """Drawn top-right when nothing is hovered."""

    def redraw(self) -> None:
        self.delete("all")
        self._hovered = None
        f = self.theme.fonts
        self.create_text(2, 4, text=self.title, anchor="nw", fill=self.p.secondary,
                         font=f["ui_bold"])
        if not self.has_data():
            x0, y0, x1, y1 = self.plot()
            self.create_text((x0 + x1) // 2, (y0 + y1) // 2, text="nothing to plot yet",
                             fill=self.p.muted, font=f["small"])
            return
        self.draw()
        self.legend()

    # -- shared drawing ----------------------------------------------------- #
    def y_axis(self, top: float, ticks: Sequence[float], fmt) -> None:
        x0, y0, x1, y1 = self.plot()
        for t in ticks:
            y = y1 - (t / top) * (y1 - y0)
            self.create_line(x0, y, x1, y, fill=self.p.chart_axis if t == 0 else self.p.chart_grid)
            self.create_text(x0 - 6, y, text=fmt(t), anchor="e", fill=self.p.muted,
                             font=self.theme.fonts["small"])

    def x_label(self, x: float, text: str, anchor: str = "n") -> None:
        _, _, _, y1 = self.plot()
        self.create_text(x, y1 + 4, text=text, anchor=anchor, fill=self.p.muted,
                         font=self.theme.fonts["small"])

    def readout(self, text: str) -> None:
        w = max(self.winfo_width(), 120)
        self.create_text(w - self.RIGHT, 5, text=text, anchor="ne", fill=self.p.text,
                         font=self.theme.fonts["small"], tags=("hover",))

    # -- hover -------------------------------------------------------------- #
    def _on_motion(self, event: tk.Event) -> None:
        if not self.has_data():
            return
        x0, y0, x1, y1 = self.plot()
        inside = x0 <= event.x <= x1 and y0 - 4 <= event.y <= y1 + self.BOTTOM
        self._set_hover(self.index_at(event.x) if inside else None)

    def _set_hover(self, i: Optional[int]) -> None:
        if i == self._hovered:
            return
        self._hovered = i
        self.delete("hover")
        self.unhover()
        if i is None:
            self.itemconfigure("legend", state="normal")
            return
        self.itemconfigure("legend", state="hidden")
        self.readout(self.draw_hover(i))

    def unhover(self) -> None:
        """Undo any restyling done by :meth:`draw_hover`."""


class LetterChart(Chart):
    title = "Letter frequency"

    def __init__(self, master: tk.Misc, theme: Theme, height: int = 160):
        self.observed: Dict[str, float] = {}
        self.expected: Dict[str, float] = {}
        super().__init__(master, theme, height)

    def set_data(self, observed: Dict[str, float], expected: Dict[str, float]) -> None:
        self.observed, self.expected = dict(observed), dict(expected)
        self.redraw()

    def has_data(self) -> bool:
        return any(self.observed.values())

    def _top(self) -> float:
        peak = max(list(self.observed.values()) + list(self.expected.values()) + [1.0])
        return max(15.0, math.ceil(peak / 5.0) * 5.0)

    def _slot(self) -> float:
        x0, _, x1, _ = self.plot()
        return (x1 - x0) / 26.0

    def draw(self) -> None:
        x0, y0, x1, y1 = self.plot()
        top = self._top()
        step = 5 if top <= 20 else 10
        self.y_axis(top, [t for t in range(0, int(top) + 1, step)], lambda t: f"{t:g}%")
        slot = self._slot()
        bar = max(2.0, min(24.0, slot - 2.0))
        for i, ch in enumerate(LETTERS):
            cx = x0 + (i + 0.5) * slot
            h = self.observed.get(ch, 0.0) / top * (y1 - y0)
            if h >= 0.5:
                self.create_rectangle(cx - bar / 2, y1 - h, cx + bar / 2, y1,
                                      fill=self.p.series, outline="",
                                      tags=("bar", f"bar{i}"))
            ey = y1 - self.expected.get(ch, 0.0) / top * (y1 - y0)
            self.create_line(cx - slot / 2 + 1, ey, cx + slot / 2 - 1, ey,
                             fill=self.p.reference, width=2, tags=("ref",))
            if slot >= 9 or i % 2 == 0:
                self.x_label(cx, ch)

    def legend(self) -> None:
        w = max(self.winfo_width(), 120)
        f = self.theme.fonts["small"]
        x = w - self.RIGHT
        t = self.create_text(x, 5, text="English", anchor="ne", fill=self.p.secondary,
                             font=f, tags=("legend",))
        x = self.bbox(t)[0] - 5
        self.create_line(x - 12, 12, x, 12, fill=self.p.reference, width=2, tags=("legend",))
        x -= 22
        t = self.create_text(x, 5, text="observed", anchor="ne", fill=self.p.secondary,
                             font=f, tags=("legend",))
        x = self.bbox(t)[0] - 5
        self.create_rectangle(x - 9, 7, x, 16, fill=self.p.series, outline="",
                              tags=("legend",))

    def index_at(self, x: int) -> Optional[int]:
        x0 = self.plot()[0]
        return max(0, min(25, int((x - x0) / self._slot())))

    def draw_hover(self, i: int) -> str:
        self.itemconfigure("bar", fill=self.p.series_dim)
        self.itemconfigure(f"bar{i}", fill=self.p.series)
        ch = LETTERS[i]
        return (f"{ch}   observed {self.observed.get(ch, 0.0):.1f}%"
                f"   English {self.expected.get(ch, 0.0):.1f}%")

    def unhover(self) -> None:
        self.itemconfigure("bar", fill=self.p.series)


class ByteChart(Chart):
    title = "Byte values"

    def __init__(self, master: tk.Misc, theme: Theme, height: int = 160):
        self.counts: List[int] = []
        super().__init__(master, theme, height)

    def set_data(self, counts: Sequence[int]) -> None:
        self.counts = list(counts)
        self.redraw()

    def has_data(self) -> bool:
        return len(self.counts) == 256 and any(self.counts)

    def draw(self) -> None:
        x0, y0, x1, y1 = self.plot()
        top = nice_ceiling(max(self.counts))
        ticks = [0, top / 2, top] if top >= 2 else [0, top]
        self.y_axis(top, ticks, lambda t: f"{t:,.0f}")
        w = (x1 - x0) / 256.0
        for b, c in enumerate(self.counts):
            if not c:
                continue
            h = max(1.0, c / top * (y1 - y0))
            xa = x0 + b * w
            self.create_rectangle(xa, y1 - h, max(xa + 1, xa + w), y1,
                                  fill=self.p.series, outline="")
        for b, label in ((0x00, "00"), (0x40, "40"), (0x80, "80"), (0xC0, "C0")):
            self.x_label(x0 + b * w, label, "nw" if b == 0 else "n")
        self.x_label(x1, "FF", "ne")

    def index_at(self, x: int) -> Optional[int]:
        x0, _, x1, _ = self.plot()
        return max(0, min(255, int((x - x0) / ((x1 - x0) / 256.0))))

    def draw_hover(self, i: int) -> str:
        x0, y0, x1, y1 = self.plot()
        x = x0 + (i + 0.5) * (x1 - x0) / 256.0
        self.create_line(x, y0, x, y1, fill=self.p.muted, tags=("hover",))
        total = sum(self.counts) or 1
        glyph = f" '{chr(i)}'" if 33 <= i < 127 else ""
        return f"0x{i:02X}{glyph}   {self.counts[i]:,}  ({100.0 * self.counts[i] / total:.1f}%)"


class EntropyChart(Chart):
    title = "Entropy along the data"
    TOP_BITS = 8.0

    def __init__(self, master: tk.Misc, theme: Theme, height: int = 150):
        self.series: List[Tuple[int, float]] = []
        self.size = 0
        super().__init__(master, theme, height)

    def set_data(self, series: Sequence[Tuple[int, float]], size: int) -> None:
        self.series, self.size = list(series), size
        self.redraw()

    def has_data(self) -> bool:
        return len(self.series) >= 2

    def _points(self) -> List[Tuple[float, float]]:
        x0, y0, x1, y1 = self.plot()
        last = max(1, self.series[-1][0])
        return [(x0 + off / last * (x1 - x0),
                 y1 - min(e, self.TOP_BITS) / self.TOP_BITS * (y1 - y0))
                for off, e in self.series]

    def draw(self) -> None:
        x0, y0, x1, y1 = self.plot()
        self.y_axis(self.TOP_BITS, [0, 2, 4, 6, 8], lambda t: f"{t:g}")
        pts = self._points()
        area = [(x0, y1)] + pts + [(x1, y1)]
        self.create_polygon(*[c for pt in area for c in pt], fill=self.p.series_wash,
                            outline="")
        for t in (2, 4, 6, 8):          # keep the grid visible through the wash
            y = y1 - t / self.TOP_BITS * (y1 - y0)
            self.create_line(x0, y, x1, y, fill=self.p.chart_grid)
        self.create_line(*[c for pt in pts for c in pt], fill=self.p.series, width=2,
                         joinstyle="round", capstyle="round")
        self.x_label(x0, "0", "nw")
        self.x_label(x1, f"{self.size:,} bytes", "ne")

    def legend(self) -> None:
        w = max(self.winfo_width(), 120)
        self.create_text(w - self.RIGHT, 5, text="bits per byte", anchor="ne",
                         fill=self.p.muted, font=self.theme.fonts["small"], tags=("legend",))

    def index_at(self, x: int) -> Optional[int]:
        pts = self._points()
        return min(range(len(pts)), key=lambda i: abs(pts[i][0] - x))

    def draw_hover(self, i: int) -> str:
        _, y0, _, y1 = self.plot()
        x, y = self._points()[i]
        self.create_line(x, y0, x, y1, fill=self.p.muted, tags=("hover",))
        self.create_oval(x - 6, y - 6, x + 6, y + 6, fill=self.surface, outline="",
                         tags=("hover",))
        self.create_oval(x - 4, y - 4, x + 4, y + 4, fill=self.p.series, outline="",
                         tags=("hover",))
        off, e = self.series[i]
        return f"offset {off:,}   {e:.2f} bits"

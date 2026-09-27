"""
aesop.gui — the graphical workbench.

``aesop gui`` opens a desktop window over the same command registry the CLI
uses: every command gets a form generated from its argument specs, output is
rendered natively (tables, panels, the field guide), and an inspector charts
the input as you type.  It is built on Tkinter from the standard library, so
it adds no dependencies.

The package is layered so that only :mod:`~aesop.gui.app` and the widget
modules touch the toolkit; ``capture``, ``forms``, ``markdown``, ``insight``,
``worker`` and ``runner`` are plain Python and import without a display.
"""
from __future__ import annotations

import sys
from typing import Optional


def run_gui(command: Optional[str] = None, theme: Optional[str] = None) -> int:
    """Open the workbench and block until it is closed.  Returns an exit code."""
    try:
        import tkinter as tk
    except ImportError:
        print("aesop gui needs Tkinter, which this Python was built without.\n"
              "  Debian/Ubuntu:  sudo apt install python3-tk\n"
              "  Fedora:         sudo dnf install python3-tkinter\n"
              "  macOS (brew):   brew install python-tk", file=sys.stderr)
        return 1
    try:
        root = tk.Tk(className="aesop")
    except tk.TclError as exc:
        print(f"aesop gui could not open a window: {exc}\n"
              "  A graphical session is required (is DISPLAY set?).", file=sys.stderr)
        return 1

    from .app import Workbench, default_prefs_path

    app = Workbench(root, prefs_path=default_prefs_path(), theme=theme, command=command)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.close()
    return 0


def main() -> int:
    """Entry point for the ``aesop-gui`` launcher."""
    from ..cli import main as cli_main
    return cli_main(["gui"] + sys.argv[1:])

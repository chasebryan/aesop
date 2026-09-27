"""
aesop.gui.worker — the process that actually runs commands for the workbench.

The window never runs a solver itself.  It keeps one of these workers warm and
talks to it over pipes, one JSON document per line:

    → {"id": 7, "argv": ["caesar", "--all", "Uryyb Jbeyq"]}
    ← {"id": 7, "kind": "start"}
    ← {"id": 7, "kind": "table", …}            (see aesop.gui.capture)
    ← {"id": 7, "kind": "done", "code": 0, "elapsed": 0.012}

Running out-of-process buys three things: the window stays responsive during a
long anneal, *Stop* can simply kill the worker, and a crash in a handler cannot
take the workbench down with it.  ``argv`` is parsed by the same parser as the
command line, so behaviour is identical to typing the command.

Run as ``python -m aesop.gui.worker``; not meant to be used by hand.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import threading
import time
import traceback
from typing import Any, Dict, List

from .capture import CaptureOutput


class _NoStdin:
    """Stands in for stdin: looks like a terminal with nothing typed.

    Handlers fall back to reading stdin when given no input; in the workbench
    that must produce their friendly "no input" error rather than swallow the
    protocol stream or block forever.
    """

    class _Buffer:
        @staticmethod
        def read(*_a: Any) -> bytes:
            return b""

    buffer = _Buffer()

    @staticmethod
    def isatty() -> bool:
        return True

    @staticmethod
    def read(*_a: Any) -> str:
        return ""

    readline = read

    @staticmethod
    def fileno() -> int:
        raise io.UnsupportedOperation("stdin is not available in the workbench")


class _EventStream(io.TextIOBase):
    """A text stream whose writes become ``stream`` events."""

    def __init__(self, name: str, channel: "_Channel"):
        self._name = name
        self._channel = channel

    def writable(self) -> bool:
        return True

    def isatty(self) -> bool:
        return False

    def write(self, s: str) -> int:
        if s:
            self._channel.emit({"kind": "stream", "name": self._name, "text": s})
        return len(s)


class _Channel:
    def __init__(self, fh):
        self._fh = fh
        self._lock = threading.Lock()
        self.request_id = 0

    def emit(self, event: Dict[str, Any]) -> None:
        event.setdefault("id", self.request_id)
        line = json.dumps(event, ensure_ascii=True, default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()


def _run(argv: List[str], parser, channel: _Channel) -> int:
    from .. import cli

    out = CaptureOutput(channel.emit)
    usage_out, usage_err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(usage_out), contextlib.redirect_stderr(usage_err):
            args = parser.parse_args(argv)
    except SystemExit as exc:            # -h, or a usage error
        if usage_out.getvalue():
            out.code(usage_out.getvalue().rstrip("\n"))
        err = usage_err.getvalue().strip()
        if err:
            # argparse prints "usage: …" then "prog: error: message"
            *usage, message = err.splitlines()
            out.error(message.split("error: ", 1)[-1])
            if usage:
                out.hint(" ".join(u.strip() for u in usage))
        return exc.code if isinstance(exc.code, int) else 2

    meta = getattr(args, "_meta", None)
    if meta in ("repl", "gui"):
        out.error(f"`{meta}` is a terminal command — you are already in the workbench")
        return 2
    try:
        if meta == "manual":
            return cli._handle_manual(args, out) or 0
        if meta == "list":
            return cli._handle_list(args, out) or 0
        if meta == "version":
            return cli._handle_version(args, out) or 0
        cmd = getattr(args, "_cmd", None)
        if cmd is None:
            out.hint("type a command, e.g.  caesar 'Wkh txlfn eurzq ira'")
            return 0
        return cmd.handler(args, out) or 0
    except Exception as exc:
        out.error(f"{type(exc).__name__}: {exc}")
        if getattr(args, "debug", False):
            out.code(traceback.format_exc().rstrip("\n"), lang="pytb")
        else:
            out.hint("add --debug in the command bar for a traceback")
        return 1


def main() -> int:
    # Keep the protocol on private copies of the pipes, then point the real
    # stdin/stdout elsewhere so neither a handler nor a child process it
    # spawns (e.g. a padding oracle) can read or corrupt the protocol.
    proto_in = os.fdopen(os.dup(0), "r", encoding="utf-8", newline="\n")
    proto_out = os.fdopen(os.dup(1), "w", encoding="utf-8", newline="\n")
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    os.dup2(2, 1)

    channel = _Channel(proto_out)
    sys.stdin = _NoStdin()  # type: ignore[assignment]
    sys.stdout = _EventStream("stdout", channel)  # type: ignore[assignment]
    sys.stderr = _EventStream("stderr", channel)  # type: ignore[assignment]

    from .. import cli
    from ..registry import REGISTRY

    cli._load_modules()
    parser = cli.build_parser()
    channel.emit({"kind": "ready", "commands": len(REGISTRY),
                  "load_errors": [list(e) for e in cli._IMPORT_ERRORS]})

    for line in proto_in:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            channel.request_id = int(req["id"])
            argv = [str(a) for a in req["argv"]]
        except (ValueError, KeyError, TypeError):
            continue
        channel.emit({"kind": "start"})
        started = time.perf_counter()
        try:
            code = _run(argv, parser, channel)
        except BaseException as exc:     # never let one request kill the loop
            if isinstance(exc, KeyboardInterrupt):
                raise
            channel.emit({"kind": "line", "style": "error",
                          "spans": [[f"{type(exc).__name__}: {exc}", ""]]})
            code = 1
        channel.emit({"kind": "done", "code": code,
                      "elapsed": round(time.perf_counter() - started, 4)})
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
aesop.gui.runner — the window's side of the worker protocol.

:class:`Runner` owns one warm :mod:`aesop.gui.worker` process.  ``submit`` sends
it a command; events come back through the ``on_event`` callback, which is
invoked **on a background thread** — a GUI must hand them to its own event loop
(the workbench uses a queue polled by ``after``).

Cancelling kills the worker and starts a fresh one, which is the only way to
stop a CPU-bound solver that never yields.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from typing import Any, Callable, Dict, List, Optional

Event = Dict[str, Any]

CANCELLED = 130      # exit code reported for a stopped run (as for Ctrl-C)
CRASHED = -1


def _worker_env() -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    # The worker must import the same aesop we are, installed or not.
    import aesop
    root = os.path.dirname(os.path.dirname(os.path.abspath(aesop.__file__)))
    env["PYTHONPATH"] = os.pathsep.join(p for p in (root, env.get("PYTHONPATH", "")) if p)
    return env


class Runner:
    def __init__(self, on_event: Callable[[Event], None]):
        self._on_event = on_event
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None
        self._next_id = 0
        self._active: Optional[int] = None      # id of the request in flight

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> None:
        """Spawn the worker if it is not running (idempotent)."""
        with self._lock:
            self._ensure()

    def _ensure(self) -> subprocess.Popen:
        if self._proc is not None and self._proc.poll() is None:
            return self._proc
        proc = subprocess.Popen(
            [sys.executable, "-m", "aesop.gui.worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            env=_worker_env(), bufsize=0,
        )
        self._proc = proc
        threading.Thread(target=self._read, args=(proc,), daemon=True,
                         name="aesop-worker-reader").start()
        return proc

    def close(self) -> None:
        with self._lock:
            proc, self._proc, self._active = self._proc, None, None
        if proc is not None:
            self._kill(proc)

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        for fh in (proc.stdin, proc.stdout):
            try:
                if fh is not None:
                    fh.close()
            except OSError:
                pass

    # -- requests ----------------------------------------------------------- #
    @property
    def busy(self) -> bool:
        return self._active is not None

    def submit(self, argv: List[str]) -> int:
        """Run ``argv`` (command name first).  Returns the request id."""
        with self._lock:
            if self._active is not None:
                raise RuntimeError("a command is already running")
            proc = self._ensure()
            self._next_id += 1
            rid = self._active = self._next_id
            payload = json.dumps({"id": rid, "argv": list(argv)}) + "\n"
            try:
                proc.stdin.write(payload.encode("utf-8"))
                proc.stdin.flush()
            except OSError as exc:
                self._active = None
                raise RuntimeError(f"could not reach the worker: {exc}") from exc
            return rid

    def cancel(self) -> bool:
        """Stop the running command, if any.  Returns True if one was stopped."""
        with self._lock:
            rid, self._active = self._active, None
            if rid is None:
                return False
            proc, self._proc = self._proc, None
        if proc is not None:
            self._kill(proc)
        self._on_event({"id": rid, "kind": "done", "code": CANCELLED, "cancelled": True})
        with self._lock:
            self._ensure()          # warm the replacement
        return True

    # -- reader thread ------------------------------------------------------ #
    def _read(self, proc: subprocess.Popen) -> None:
        try:
            for raw in proc.stdout:
                try:
                    event = json.loads(raw.decode("utf-8"))
                except ValueError:
                    continue
                if event.get("kind") == "done":
                    with self._lock:
                        if self._active == event.get("id"):
                            self._active = None
                        else:
                            continue        # a run we already gave up on
                self._on_event(event)
        except (OSError, ValueError):
            pass
        # EOF.  If a request was still in flight on *this* worker, it crashed.
        with self._lock:
            if self._proc is not proc:
                return
            rid, self._active, self._proc = self._active, None, None
        if rid is not None:
            self._on_event({"id": rid, "kind": "line", "style": "error",
                            "spans": [["the worker process exited unexpectedly", ""]]})
            self._on_event({"id": rid, "kind": "done", "code": CRASHED, "crashed": True})

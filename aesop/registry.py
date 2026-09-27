"""
aesop.registry — the plug-in contract.

Every capability in AESOP is a :class:`Command`.  Modules register their
commands at import time with the :func:`command` decorator; the CLI
(:mod:`aesop.cli`) discovers the registry, builds an ``argparse`` parser from
it, and dispatches.  This keeps each technique in its own file and lets the
tool grow without a central switchboard.

A handler has the signature ``handler(args, out) -> int`` where ``args`` is the
parsed ``argparse.Namespace`` and ``out`` is an :class:`aesop.ui.Output`.  A
return of ``0`` means success.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# Human-readable group labels, ordered for help output.
GROUPS: Dict[str, str] = {
    "analysis": "Analysis & triage",
    "classical": "Classical ciphers",
    "modern": "Modern & math attacks",
    "encoding": "Encodings & formats",
    "network": "Network & forensics",
    "meta": "Reference & tooling",
}


@dataclass
class Arg:
    """A single CLI argument spec (thin wrapper over argparse add_argument)."""

    name: str
    help: str = ""
    kwargs: Dict[str, Any] = field(default_factory=dict)


def arg(name: str, help: str = "", **kwargs: Any) -> Arg:
    return Arg(name=name, help=help, kwargs=kwargs)


def io_args(positional: str = "text", positional_help: str = "input value (or pipe via stdin / use --file)") -> List["Arg"]:
    """Standard input-argument trio shared by every data-taking command.

    Adds an optional positional plus ``--file`` and ``--in-encoding`` so users
    can pass data literally, from a file, or over a pipe, in raw/hex/base64.
    Read them back with :func:`aesop.core.io.load`.
    """
    # dest is always "text" (what io.load reads); `positional` is only the
    # display metavar. This keeps io.load(args) working no matter what a command
    # names its positional.
    return [
        Arg("text", positional_help, {"nargs": "?", "metavar": positional}),
        Arg("-f --file", "read input from a file instead", {"metavar": "PATH"}),
        Arg(
            "-e --in-encoding",
            "input encoding (default: autodetect)",
            {
                "default": "auto",
                "choices": ["auto", "raw", "hex", "base64", "base64url"],
            },
        ),
    ]


HandlerT = Callable[[Any, Any], int]


@dataclass
class Command:
    name: str
    group: str
    summary: str
    handler: HandlerT
    args: List[Arg] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    manual: str = ""
    examples: List[str] = field(default_factory=list)
    description: str = ""


REGISTRY: Dict[str, Command] = {}
_ALIASES: Dict[str, str] = {}


def command(
    name: str,
    *,
    group: str,
    summary: str,
    args: Optional[List[Arg]] = None,
    aliases: Optional[List[str]] = None,
    manual: str = "",
    examples: Optional[List[str]] = None,
    description: str = "",
) -> Callable[[HandlerT], HandlerT]:
    """Decorator registering ``handler`` as a CLI command."""

    def deco(fn: HandlerT) -> HandlerT:
        if group not in GROUPS:
            raise ValueError(f"unknown group {group!r}; add it to registry.GROUPS")
        if name in REGISTRY:
            raise ValueError(f"duplicate command {name!r}")
        cmd = Command(
            name=name,
            group=group,
            summary=summary,
            handler=fn,
            args=args or [],
            aliases=aliases or [],
            manual=manual,
            examples=examples or [],
            description=description or fn.__doc__ or "",
        )
        REGISTRY[name] = cmd
        for a in cmd.aliases:
            _ALIASES[a] = name
        return fn

    return deco


def resolve(name: str) -> Optional[Command]:
    if name in REGISTRY:
        return REGISTRY[name]
    if name in _ALIASES:
        return REGISTRY[_ALIASES[name]]
    return None


def commands_by_group() -> Dict[str, List[Command]]:
    out: Dict[str, List[Command]] = {g: [] for g in GROUPS}
    for cmd in REGISTRY.values():
        out.setdefault(cmd.group, []).append(cmd)
    for g in out:
        out[g].sort(key=lambda c: c.name)
    return out

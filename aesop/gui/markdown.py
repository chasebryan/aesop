"""
aesop.gui.markdown — just enough Markdown to show the field guide.

The manual pages use a small, regular subset: headings, paragraphs, fenced
code, bullet/numbered lists, block quotes, pipe tables, and inline
``code`` / **bold** / *italic* / [links](…).  This parses that subset into
plain data the workbench can lay out; it is not a general Markdown engine.

Toolkit-free.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple

# (text, styles, href) — styles drawn from {"bold", "italic", "code"}
Inline = Tuple[str, Tuple[str, ...], str]


@dataclass
class Block:
    kind: str                       # heading | para | code | item | quote | table | rule
    spans: List[Inline] = field(default_factory=list)
    level: int = 0                  # heading level / list nesting depth
    marker: str = ""                # list bullet as shown ("•", "1.")
    text: str = ""                  # code body
    lang: str = ""
    header: List[List[Inline]] = field(default_factory=list)
    rows: List[List[List[Inline]]] = field(default_factory=list)


_INLINE = re.compile(
    r"(?P<code>`+)(?P<code_body>.+?)(?P=code)"
    r"|\*\*(?P<bold>.+?)\*\*"
    r"|(?<![\w*])\*(?P<italic>[^\s*](?:.*?[^\s*])?)\*(?![\w*])"
    r"|\[(?P<label>[^\]]+)\]\((?P<href>[^)\s]+)\)"
)


def parse_inline(text: str, styles: Tuple[str, ...] = (), href: str = "") -> List[Inline]:
    out: List[Inline] = []
    pos = 0
    for m in _INLINE.finditer(text):
        if m.start() > pos:
            out.append((text[pos:m.start()], styles, href))
        pos = m.end()
        if m.group("code"):
            out.append((m.group("code_body").strip(), styles + ("code",), href))
        elif m.group("bold") is not None:
            out.extend(parse_inline(m.group("bold"), styles + ("bold",), href))
        elif m.group("italic") is not None:
            out.extend(parse_inline(m.group("italic"), styles + ("italic",), href))
        else:
            out.extend(parse_inline(m.group("label"), styles, m.group("href")))
    if pos < len(text):
        out.append((text[pos:], styles, href))
    return out


def inline_text(spans: List[Inline]) -> str:
    return "".join(s[0] for s in spans)


_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_ITEM = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})\s*([\w+-]*)\s*$")
_RULE = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def _split_row(line: str) -> List[str]:
    """Split a pipe-table row, leaving pipes inside `code` or escaped alone."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    cells, cur, in_code, i = [], [], False, 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if ch == "`":
            in_code = not in_code
        if ch == "|" and not in_code:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    if "".join(cur).strip():
        cells.append("".join(cur).strip())
    return cells


def parse(md: str) -> List[Block]:
    lines = md.replace("\r\n", "\n").split("\n")
    blocks: List[Block] = []
    para: List[str] = []
    i = 0

    def flush() -> None:
        if para:
            blocks.append(Block("para", parse_inline(" ".join(s.strip() for s in para))))
            para.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        fence = _FENCE.match(line)
        if fence:
            flush()
            mark, lang = fence.group(1), fence.group(2)
            body: List[str] = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith(mark[:3]):
                body.append(lines[i])
                i += 1
            i += 1                                   # closing fence
            blocks.append(Block("code", text="\n".join(body), lang=lang))
            continue

        if not stripped or stripped.startswith("<!--"):
            flush()
            i += 1
            continue

        heading = _HEADING.match(line)
        if heading:
            flush()
            blocks.append(Block("heading", parse_inline(heading.group(2)),
                                level=len(heading.group(1))))
            i += 1
            continue

        if _RULE.match(line):
            flush()
            blocks.append(Block("rule"))
            i += 1
            continue

        if stripped.startswith("|") and i + 1 < len(lines) and _TABLE_SEP.match(lines[i + 1]):
            flush()
            header = [parse_inline(c) for c in _split_row(line)]
            i += 2
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append([parse_inline(c) for c in _split_row(lines[i])])
                i += 1
            blocks.append(Block("table", header=header, rows=rows))
            continue

        if stripped.startswith(">"):
            flush()
            quote: List[str] = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip()[1:].strip())
                i += 1
            blocks.append(Block("quote", parse_inline(" ".join(q for q in quote if q))))
            continue

        item = _ITEM.match(line)
        if item:
            flush()
            indent, marker, text = item.groups()
            parts = [text]
            i += 1
            # continuation lines: indented prose that is not a new block
            while i < len(lines) and lines[i].strip() and lines[i][:1] in (" ", "\t") \
                    and not _ITEM.match(lines[i]) and not _FENCE.match(lines[i]):
                parts.append(lines[i].strip())
                i += 1
            blocks.append(Block(
                "item", parse_inline(" ".join(parts)),
                level=len(indent.expandtabs(4)) // 2,
                marker=marker if marker[0].isdigit() else "•",
            ))
            continue

        para.append(line)
        i += 1

    flush()
    return blocks

"""
aesop.manual — the built-in field guide.

Every technique AESOP can run ships with a manual page explaining the *theory*,
*when to reach for it*, and *how to drive it from the CLI*.  Pages are plain
Markdown in ``aesop/manual/pages/*.md`` so they double as browsable docs.

    aesop manual                 # list every topic
    aesop manual vigenere        # render one page
    aesop manual --search key    # find pages mentioning a term

Convention for a page ``pages/<slug>.md``:

    # Title Of The Page
    > One-line summary shown in the index.
    <body markdown…>
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

_PAGES_DIR = os.path.join(os.path.dirname(__file__), "pages")


@dataclass
class ManualPage:
    slug: str
    title: str
    summary: str
    path: str

    def body(self) -> str:
        with open(self.path, encoding="utf-8") as fh:
            return fh.read()


def _parse_header(path: str) -> tuple[str, str]:
    title = os.path.splitext(os.path.basename(path))[0]
    summary = ""
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                s = line.strip()
                if s.startswith("# ") and title == os.path.splitext(os.path.basename(path))[0]:
                    title = s[2:].strip()
                elif s.startswith("> ") and not summary:
                    summary = s[2:].strip()
                    break
                elif summary:
                    break
    except OSError:
        pass
    return title, summary


def load_manual() -> Dict[str, ManualPage]:
    """Discover every manual page keyed by slug."""
    pages: Dict[str, ManualPage] = {}
    if not os.path.isdir(_PAGES_DIR):
        return pages
    for fn in sorted(os.listdir(_PAGES_DIR)):
        if not fn.endswith(".md"):
            continue
        slug = fn[:-3]
        path = os.path.join(_PAGES_DIR, fn)
        title, summary = _parse_header(path)
        pages[slug] = ManualPage(slug=slug, title=title, summary=summary, path=path)
    return pages


def get_page(slug: str) -> Optional[ManualPage]:
    pages = load_manual()
    if slug in pages:
        return pages[slug]
    # fuzzy: prefix / substring match
    matches = [p for s, p in pages.items() if slug.lower() in s.lower()]
    if len(matches) == 1:
        return matches[0]
    return None


def search_manual(term: str) -> List[ManualPage]:
    """Full-text search across manual pages."""
    term_l = term.lower()
    hits: List[ManualPage] = []
    for page in load_manual().values():
        if term_l in page.title.lower() or term_l in page.summary.lower():
            hits.append(page)
            continue
        try:
            if term_l in page.body().lower():
                hits.append(page)
        except OSError:
            pass
    return hits

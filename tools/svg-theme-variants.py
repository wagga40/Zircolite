#!/usr/bin/env python3
"""
Write fixed light and dark copies of a docs explainer SVG.

The explainers in docs/pics pick their palette with `prefers-color-scheme`
inside the file. Safari evaluates that against the system appearance rather
than the page, so on GitHub, whose theme can differ from the system one, the
README showed a dark diagram on a light page. The README shows these copies
through <picture> instead, and GitHub picks the one for its theme; the docs
site follows the system appearance and keeps the original.

Edit the original only, then regenerate its copies:

  pdm run python tools/svg-theme-variants.py docs/pics/how-it-works.svg

tests/test_tools.py fails while a copy differs from what this writes.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

DARK_BLOCK = re.compile(r"\n[ \t]*@media \(prefers-color-scheme: dark\) \{\s*(:root \{[^}]*\})\s*\}[ \t]*\n")
ROOT_BLOCK = re.compile(r":root \{[^}]*\}")


def variants(text: str) -> tuple[str, str]:
    """The light and dark copies of an SVG whose dark palette is one @media block over :root."""
    match = DARK_BLOCK.search(text)
    if match is None:
        raise ValueError("no `@media (prefers-color-scheme: dark) { :root { ... } }` block to bake")
    light = text[:match.start()] + "\n" + text[match.end():]
    dark = ROOT_BLOCK.sub(lambda _: match.group(1), light, count=1)
    return light, dark


def copies(source: Path) -> tuple[Path, Path]:
    return source.with_name(f"{source.stem}-light.svg"), source.with_name(f"{source.stem}-dark.svg")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write fixed light and dark copies of a docs explainer SVG.")
    parser.add_argument("sources", nargs="+", type=Path, help="Explainer SVGs whose copies to write")
    args = parser.parse_args(argv)
    for source in args.sources:
        for path, text in zip(copies(source), variants(source.read_text(encoding="utf-8")), strict=True):
            path.write_text(text, encoding="utf-8")
            print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

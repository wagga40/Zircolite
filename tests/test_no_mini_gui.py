"""The package viewer replaced the Mini-GUI; nothing Zircolite ships may still offer the old one."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent

# What ships or documents the product. The viewer's own sources and build are new and cannot mention the
# old GUI; docs/superpowers and .superpowers are local planning notes, never shipped.
SHIPPED = ["README.md", "docs", "config", "templates", "zircolite", "tools", "Taskfile.yml", "Dockerfile",
           ".dockerignore", ".github", ".forgejo", "Zircolite.spec"]
OLD = re.compile(r"mini-?gui|zircogui|exportForZircoGui|ZircoliteGuiGenerator|gui_dev", re.IGNORECASE)


def shipped_files():
    for name in SHIPPED:
        path = ROOT / name
        if path.is_file():
            yield path
        elif path.is_dir():
            yield from (p for p in path.rglob("*") if p.is_file() and "superpowers" not in p.parts and p.suffix not in {".png", ".jpg", ".webp", ".gz", ".wasm", ".zip"})


@pytest.mark.xfail(strict=True, reason="README, docs and CI move in Tasks 3–4")
def test_nothing_shipped_mentions_the_mini_gui():
    found = []
    for path in shipped_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        found += [f"{path.relative_to(ROOT)}:{n}" for n, line in enumerate(text.splitlines(), 1) if OLD.search(line)]
    assert found == [], "the Mini-GUI was replaced by the package viewer; update these lines"

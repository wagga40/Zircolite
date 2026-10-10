"""Fail the build when a documentation link points nowhere.

The docs move content between pages and link across them by heading anchor.
GitHub and docsify both render a dead anchor as a link that silently goes to
the top of the page, so nothing but a test notices one.

Anchors are computed the way GitHub computes them, which docsify matches for
the headings these pages use.
"""

import re
from pathlib import Path

import pytest

WORKSPACE_ROOT = Path(__file__).parent.parent
DOCS = WORKSPACE_ROOT / "docs"
PICS = DOCS / "pics"

PAGES = sorted(
    [WORKSPACE_ROOT / "README.md", WORKSPACE_ROOT / "CONTRIBUTING.md", *DOCS.glob("*.md")]
)

FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
EXPLICIT_ANCHOR = re.compile(r"<a\s+(?:id|name)=\"([^\"]+)\"")
MD_LINK = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
HTML_SRC = re.compile(r"<(?:img|source|video)\b[^>]*\bsrc(?:set)?=\"([^\"]+)\"")
INLINE_CODE = re.compile(r"`[^`]*`")


def prose_lines(path: Path) -> list[str]:
    """The lines of a page outside fenced code, where `# comment` is not a heading."""
    lines, in_fence = [], False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    return lines


def slug(heading: str) -> str:
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    found: set[str] = set()
    seen: dict[str, int] = {}
    for line in prose_lines(path):
        found.update(EXPLICIT_ANCHOR.findall(line))
        match = HEADING.match(line)
        if not match:
            continue
        base = slug(match.group(2))
        count = seen.get(base, 0)
        seen[base] = count + 1
        found.add(base if count == 0 else f"{base}-{count}")
    return found


def links(path: Path) -> list[str]:
    targets = []
    for line in prose_lines(path):
        bare = INLINE_CODE.sub("", line)
        targets += MD_LINK.findall(bare) + HTML_SRC.findall(bare)
    return [t for t in targets if not re.match(r"^[a-z][a-z0-9+.-]*:", t)]


@pytest.mark.parametrize("page", PAGES, ids=lambda p: str(p.relative_to(WORKSPACE_ROOT)))
def test_every_link_resolves(page):
    broken = []
    for target in links(page):
        path_part, _, anchor = target.partition("#")
        dest = (page.parent / path_part).resolve() if path_part else page
        if not dest.exists():
            broken.append(f"{target} (no such file)")
        elif anchor and dest.suffix == ".md" and anchor not in anchors(dest):
            broken.append(f"{target} (no such anchor in {dest.name})")
    assert broken == [], f"{page.name} has dead links: {broken}"


def test_every_picture_in_docs_is_used():
    """A picture nothing shows still ships in every release archive."""
    referenced = {
        (page.parent / target.partition("#")[0]).resolve()
        for page in PAGES
        for target in links(page)
    }
    unused = sorted(p.name for p in PICS.iterdir() if p.is_file() and p.resolve() not in referenced)
    assert unused == [], f"docs/pics holds files no page shows: {unused}"


class TestTheCheckerItself:
    """The helpers above decide what counts as broken; pin their edge cases."""

    def test_slug_follows_github(self):
        assert slug("Rulesets / rules") == "rulesets--rules"
        assert slug("Wrapping for `file://`") == "wrapping-for-file"
        assert slug("Field mappings, exclusions, aliases, and splitting") == (
            "field-mappings-exclusions-aliases-and-splitting"
        )

    def test_comments_in_code_blocks_are_not_headings(self, tmp_path):
        page = tmp_path / "page.md"
        page.write_text("# Title\n\n```shell\n# not a heading\n```\n", encoding="utf-8")
        assert anchors(page) == {"title"}

    def test_repeated_headings_are_numbered(self, tmp_path):
        page = tmp_path / "page.md"
        page.write_text("## Output\n\n### Output\n", encoding="utf-8")
        assert anchors(page) == {"output", "output-1"}

    def test_links_inside_inline_code_are_ignored(self, tmp_path):
        page = tmp_path / "page.md"
        page.write_text("Write `[x](missing.md)` and [y](https://example.com).\n", encoding="utf-8")
        assert links(page) == []

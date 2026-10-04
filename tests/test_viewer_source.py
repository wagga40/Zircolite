"""The viewer's source and build: what Python packages, and what the page may do."""

import hashlib
import json
import re
from pathlib import Path

import pytest

from zircolite.package import PACKAGE_FORMAT

ROOT = Path(__file__).parent.parent
SOURCE = ROOT / "gui_src"
BUILD = ROOT / "gui" / "viewer"
CSP = ("default-src 'none'; script-src 'self' 'wasm-unsafe-eval' blob:; worker-src blob:; "
       "connect-src blob: data:; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:")
ENGINE = ["duckdb-eh.wasm.gz", "duckdb-browser-eh.worker.js", "parquet.duckdb_extension.wasm"]
# Log text reaches the page; none of these may ever turn it into markup or code.
SINKS = re.compile(
    r"\{@html|\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|\bFunction\s*\("
    r"|\bset(?:Timeout|Interval)\(\s*['\"`]|(?i:srcdoc)|\[\s*['\"`](?:inner|outer)HTML['\"`]\s*\]")
SCANNED = (".ts", ".svelte", ".js", ".mjs")


def test_viewer_description_matches_the_build():
    meta = json.loads((BUILD / "viewer.json").read_text(encoding="utf-8"))

    assert meta["data_format"] == PACKAGE_FORMAT
    assert meta["wrap"] == ENGINE
    assert meta["copy"] == ["index.html", "app.js", "app.css", "THIRD_PARTY_NOTICES.txt"]
    for name in meta["copy"] + meta["wrap"]:
        assert (BUILD / name).is_file(), name


def test_viewer_and_writer_agree_on_the_format():
    text = (SOURCE / "src" / "engine" / "manifest.ts").read_text(encoding="utf-8")

    assert re.search(r"export const PACKAGE_FORMAT = (\d+);", text).group(1) == str(PACKAGE_FORMAT)


@pytest.mark.parametrize("page", [SOURCE / "index.html", BUILD / "index.html"])
def test_page_forbids_network_and_inline_code(page):
    html = page.read_text(encoding="utf-8")

    assert f'<meta http-equiv="Content-Security-Policy" content="{CSP}">' in html
    assert re.findall(r"<script\b[^>]*>", html) == ['<script src="app.js">']
    assert not re.search(r"\son[a-z]+\s*=", html)


def test_viewer_source_never_turns_text_into_markup_or_code():
    files = sorted(path for path in (SOURCE / "src").rglob("*") if path.suffix in SCANNED)
    offenders = [f"{path.relative_to(ROOT)}:{number}"
                 for path in files
                 for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
                 if SINKS.search(line)]

    assert files and offenders == []


@pytest.mark.parametrize("line", [
    "{@html text}", "node.innerHTML = text", "node.outerHTML = text", "node.insertAdjacentHTML('beforeend', text)",
    "document.write(text)", "eval(text)", "eval (text)", "new Function(text)", "const f = Function('return 1');",
    "setTimeout('run()', 10)", 'setInterval("run()", 10)', "setTimeout(`${text}`, 0)",
    "<iframe srcdoc={text}></iframe>", "frame.srcdoc = text", "frame.srcDoc = text",
    "node['innerHTML'] = text", 'node["outerHTML"] = text', "node[ `innerHTML` ] = text",
])
def test_the_guard_catches_each_sink(line):
    assert SINKS.search(line)


@pytest.mark.parametrize("line", [
    "setTimeout(() => run(), 10)", "setInterval(tick, 1000)", "isFunction(value)", "typeof f === 'function'",
    "node.textContent = text", "evaluate(query)", "retrieval(query)", "node['textContent'] = text",
])
def test_the_guard_lets_ordinary_code_through(line):
    assert not SINKS.search(line)


def test_bundled_parquet_extension_is_the_pinned_one():
    pinned = re.search(r"EXTENSION_SHA256 = '([0-9a-f]{64})'",
                       (SOURCE / "scripts" / "finalize.mjs").read_text(encoding="utf-8")).group(1)

    assert hashlib.sha256((BUILD / "parquet.duckdb_extension.wasm").read_bytes()).hexdigest() == pinned

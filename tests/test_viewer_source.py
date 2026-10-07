"""The viewer's source and build: what Python packages, and what the page may do."""

import ast
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
       "connect-src blob: data:; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
       "font-src data:; base-uri 'none'; form-action 'none'")
ENGINE = ["duckdb-eh.wasm.gz", "duckdb-browser-eh.worker.js", "parquet.duckdb_extension.wasm"]
# Log text reaches the page; none of these may ever turn it into markup or code.
SINKS = re.compile(
    r"\{@html|\.innerHTML|\.outerHTML|\[\s*['\"`](?:inner|outer)HTML['\"`]\s*\]|insertAdjacentHTML"
    r"|document\.write|\beval\s*\(|(?<![\w.])Function\s*\(|(?i:srcdoc)"
    r"|set(?:Timeout|Interval)\s*\(\s*['\"`]"
)
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
    "setTimeout('run()', 10)", "setTimeout ('run()', 10)", 'setInterval("run()", 10)', "setTimeout(`${text}`, 0)",
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


def test_attack_catalogue_follows_zircolites_tactics():
    from zircolite.attack import TACTIC_ORDER

    catalogue = json.loads((ROOT / "gui_src" / "src" / "attack" / "catalog.json").read_text(encoding="utf-8"))
    assert [t["shortname"] for t in catalogue["tactics"]] == list(TACTIC_ORDER)
    active = {t["id"] for t in catalogue["techniques"]}
    assert set(catalogue["revoked"].values()) <= active


def test_only_the_viewer_build_ships_from_gui():
    """gui/ holds the sources and their node_modules too; the binary and the image take the build alone."""
    spec = ast.parse((ROOT / "Zircolite.spec").read_text(encoding="utf-8"))
    datas = next(node.value for node in spec.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "datas" for target in node.targets))
    bundled = [ast.literal_eval(element)[0] for element in datas.elts]
    assert [source for source in bundled if source.split("/")[0] == "gui"] == ["gui/viewer"]

    copied = [token.rstrip("/")
              for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
              if line.startswith("COPY ")
              for token in line.split()[1:-1] if not token.startswith("--")]
    assert not [source for source in copied if re.search(r"(^|/)gui$", source)]
    assert len([source for source in copied if source.endswith("gui/viewer")]) == 2


def test_viewer_notices_carry_the_attack_terms():
    notices = (ROOT / "gui" / "viewer" / "THIRD_PARTY_NOTICES.txt").read_text(encoding="utf-8")
    assert "MITRE ATT&CK" in notices
    assert "The MITRE Corporation" in notices


def test_severity_inks_go_through_one_helper():
    pattern = re.compile(r"""--sev-['"`]?\s*(\$\{|\+)""")
    offenders = [
        f"{path.relative_to(ROOT)}:{n}"
        for path in (ROOT / "gui_src" / "src").rglob("*")
        if path.suffix in {".ts", ".svelte"} and path.name != "levels.ts"
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.search(line)
    ]
    assert offenders == [], "build severity inks with levelInk or levelVar, so an unknown level has one colour"

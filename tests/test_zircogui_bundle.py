"""The bundled Mini-GUI must treat log-derived strings as text, never as HTML.

Field names, field values and the rule title all reach the page from the
analysed logs. The GUI used to concatenate them into HTML strings handed to
jQuery ``append`` (table headers, select options), to RowGroup (whose default
label is appended as HTML) and to vis-timeline (whose XSS filter was told to
keep ``onclick``). A crafted event therefore ran script in the analyst's
browser. These checks read the JavaScript shipped in ``gui/zircogui.zip``.
"""
import re
import zipfile
from pathlib import Path

import pytest

ZIP = Path(__file__).parent.parent / "gui" / "zircogui.zip"


@pytest.fixture(scope="module")
def gui_js():
    with zipfile.ZipFile(ZIP) as zf:
        return {
            name: zf.read(f"zircogui/js/{name}").decode("utf-8")
            for name in ("index.js", "functions.js")
        }


def test_table_headers_are_built_as_text(gui_js):
    index = gui_js["index.js"]
    assert not re.search(r"""["']<th>["']\s*\+\s*item""", index)
    assert index.count('$("<th>").text(item)') == 2  # header and footer


def test_select_options_are_built_as_text(gui_js):
    functions = gui_js["functions.js"]
    assert "<option value=" not in functions
    assert "$('<option>').val(text).text(text)" in functions
    assert functions.count("append(textOption(") == 3


def test_row_group_label_is_a_text_node(gui_js):
    functions = gui_js["functions.js"]
    assert "rowGroup: {dataSrc: 'title', startRender: textGroupLabel}" in functions
    assert "document.createTextNode(String(group))" in functions


def test_timeline_items_are_dom_nodes_without_inline_handlers(gui_js):
    index = gui_js["index.js"]
    assert "onclick" not in index
    assert 'document.createTextNode(event["title"] + " - EventID : " + event["EventID"]' in index
    assert "content: itemContent," in index


def test_archive_still_carries_the_page_assets():
    """Rebuilding the archive for the patch must not have dropped anything."""
    with zipfile.ZipFile(ZIP) as zf:
        names = set(zf.namelist())
        assert zf.testzip() is None
    for asset in (
        "zircogui/index.html",
        "zircogui/vendor/jquery/jquery.min.js",
        "zircogui/vendor/datatablesOrg/datatables.min.js",
        "zircogui/vendor/vis-timeline/vis-timeline-graph2d.min.js",
        "zircogui/js/mitre.js",
    ):
        assert asset in names

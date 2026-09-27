"""Directory discovery must retain equivalent input suffixes and user filters."""

import argparse
import bz2
import gzip
import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

from zircolite.cli import discover_files

ROOT = Path(__file__).resolve().parent.parent


def discovery_args(path, **overrides):
    values = dict(
        evtx=str(path), fileext=None, file_pattern=None, no_recursion=False,
        select=None, avoid=None,
    )
    values.update(overrides)
    values['_explicit'] = set(overrides)
    return argparse.Namespace(**values)


@pytest.mark.parametrize('second_name', [
    'b.jsonl', 'b.ndjson', 'b.json.gz', 'b.jsonl.bz2', 'b.JSONL.GZ',
])
def test_autodetected_directory_processes_equivalent_json_files(tmp_path, second_name):
    """Rediscovery must not silently discard a second supported JSON input."""
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    (inputs / 'a.json').write_text('{"Value":"first"}\n')
    content = b'{"Value":"second"}\n'
    if second_name.lower().endswith('.gz'):
        content = gzip.compress(content)
    elif second_name.lower().endswith('.bz2'):
        content = bz2.compress(content)
    (inputs / second_name).write_bytes(content)
    config = tmp_path / 'config.json'
    config.write_text('{}')
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps([{'title': 'All events', 'rule': ['SELECT * FROM logs']}]))
    output = tmp_path / 'results.json'

    result = subprocess.run(
        [sys.executable, str(ROOT / 'zircolite.py'), '-e', str(inputs),
         '-r', str(rules), '-c', str(config), '-o', str(output),
         '-l', str(tmp_path / 'run.log'), '--quiet', '--no-parallel'],
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    matches = [event for rule in json.loads(output.read_text()) for event in rule['matches']]
    assert {event['Value'] for event in matches} == {'first', 'second'}


@pytest.mark.parametrize('format_flags,names', [
    ({}, {'a.evtx', 'b.EVTX', 'c.evtx.gz', 'd.evtx.bz2'}),
    ({'json_input': True}, {'a.json', 'b.JSONL', 'c.ndjson.gz', 'd.json.bz2', 'e.json.zip'}),
    ({'json_array_input': True}, {'a.json', 'b.JSON', 'c.json.gz'}),
    ({'csv_input': True}, {'a.csv', 'b.tsv', 'c.TSV.BZ2'}),
    ({'xml_input': True}, {'a.xml', 'b.XML.GZ'}),
    ({'auditd_input': True}, {'a.log', 'b.LOG.BZ2'}),
])
def test_default_discovery_includes_format_aliases_and_compression(tmp_path, format_flags, names):
    for name in names | {'ignored.txt', 'ignored.log.1'}:
        (tmp_path / name).touch()
    found = discover_files(discovery_args(tmp_path, **format_flags), logging.getLogger(__name__))
    assert {path.name for path in found} == names


def test_default_discovery_does_not_expand_to_other_formats_when_evtx_exists(tmp_path):
    for name in ('events.evtx', 'detections.json', 'run.log'):
        (tmp_path / name).touch()
    found = discover_files(discovery_args(tmp_path), logging.getLogger(__name__))
    assert {path.name for path in found} == {'events.evtx'}


@pytest.mark.parametrize('overrides,expected', [
    ({'fileext': 'json'}, {'a.json'}),
    ({'fileext': 'jsonl'}, {'b.jsonl'}),
    ({'file_pattern': '*.json'}, {'a.json'}),
    ({'fileext': 'json', 'file_pattern': '*.jsonl'}, {'b.jsonl'}),
    ({'file_pattern': '*'}, {'a.json', 'b.jsonl', 'c.json.gz'}),
])
def test_explicit_discovery_filters_stay_exact_and_exclude_directories(tmp_path, overrides, expected):
    for name in ('a.json', 'b.jsonl', 'c.json.gz'):
        (tmp_path / name).touch()
    (tmp_path / 'directory.json').mkdir()
    (tmp_path / 'directory.jsonl').mkdir()
    args = discovery_args(tmp_path, json_input=True, **overrides)
    found = discover_files(args, logging.getLogger(__name__))
    assert {path.name for path in found} == expected


@pytest.mark.parametrize('no_recursion,expected', [
    (False, {'keep.json', 'nested/keep.jsonl.gz'}),
    (True, {'keep.json'}),
])
def test_expanded_discovery_respects_recursion_selection_and_exclusion(tmp_path, no_recursion, expected):
    (tmp_path / 'nested').mkdir()
    for name in ('keep.json', 'nested/keep.jsonl.gz', 'keep_skip.ndjson', 'other.json'):
        (tmp_path / name).touch()
    args = discovery_args(
        tmp_path, json_input=True, no_recursion=no_recursion, select=[['keep']], avoid=[['skip']],
    )
    found = discover_files(args, logging.getLogger(__name__))
    assert {str(path.relative_to(tmp_path)) for path in found} == expected


def test_discovery_keeps_content_detection_fallback_for_unrecognized_suffixes(tmp_path):
    (tmp_path / 'events.data').touch()
    (tmp_path / 'nested').mkdir()
    found = discover_files(discovery_args(tmp_path), logging.getLogger(__name__))
    assert {path.name for path in found} == {'events.data'}

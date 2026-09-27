"""Regression coverage for input retention, transforms and timestamp handling."""
import json
import logging
import sqlite3
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

from zircolite.cli import _apply_detection_result
from zircolite.config import ProcessingConfig
from zircolite.detector import LogTypeDetector
from zircolite.rules import EventFilter
from zircolite.streaming import StreamingEventProcessor

ROOT = Path(__file__).resolve().parent.parent


def write_json(path, value):
    path.write_text(json.dumps(value))
    return path


def run_cli(tmp_path, source, rules, *options):
    output = tmp_path / 'results.json'
    completed = subprocess.run(
        [sys.executable, str(ROOT / 'zircolite.py'), '-e', str(source),
         '-r', str(rules), '-o', str(output), '-l', str(tmp_path / 'run.log'),
         '--quiet', *map(str, options)],
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(output.read_text())


@pytest.mark.parametrize('backend', ['python', 'auto'])
def test_non_alias_transform_runs_once(tmp_path, backend):
    config = write_json(tmp_path / 'config.json', {
        'transforms_enabled': True,
        'transforms': {'Value': [{
            'alias': False, 'source_condition': ['json_input'],
            'code': 'def transform(param):\n    return param + "!"',
        }]},
    })
    processor = StreamingEventProcessor(
        str(config), Namespace(json_input=True), ProcessingConfig(flatten_backend=backend))
    # A nested leaf with the same flattened name is a working control.
    assert processor._flatten_event({'Event': {'Value': 'x'}}, 'source')['Value'] == 'x!'
    assert processor._flatten_event({'Value': 'x'}, 'source')['Value'] == 'x!'


@pytest.mark.parametrize('bad_kind', ['corrupt', 'missing_logs'])
def test_skipped_database_is_reported_as_failed(tmp_path, bad_kind):
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    rules = write_json(tmp_path / 'rules.json', [
        {'title': 'all', 'rule': ['SELECT * FROM logs']},
    ])
    with sqlite3.connect(inputs / 'good.db') as db:
        db.execute('CREATE TABLE logs(row_id INTEGER PRIMARY KEY, Value TEXT)')
        db.execute("INSERT INTO logs(Value) VALUES ('event')")
    bad = inputs / 'bad.db'
    if bad_kind == 'corrupt':
        bad.write_bytes(b'not a database; preserve me')
    else:
        with sqlite3.connect(bad) as db:
            db.execute('CREATE TABLE other_table(Value TEXT)')
    original = bad.read_bytes()
    report = tmp_path / 'performance.json'
    results = run_cli(tmp_path, inputs, rules, '-D', '--performance-json', report)
    assert results[0]['count'] == 1
    performance = json.loads(report.read_text())
    assert performance['status'] == 'partial'
    assert next(record for record in performance['files'] if record['sources'] == [str(bad)])['status'] == 'failed'
    assert bad.read_bytes() == original


@pytest.mark.parametrize('raw,mapped', [('timestamp', 'SystemTime'), ('@timestamp', 'Recorded_At')])
def test_correlation_auto_timestamp_uses_mapped_name(tmp_path, raw, mapped):
    config = write_json(tmp_path / 'config.json', {'mappings': {raw: mapped}})
    source = tmp_path / 'events.jsonl'
    source.write_text(''.join(json.dumps({
        raw: f'2026-01-01T00:00:0{i}Z', 'EventID': 1, 'Computer': 'host',
    }) + '\n' for i in range(2)))
    rules = tmp_path / 'rules.yml'
    rules.write_text(yaml.safe_dump_all([
        {'title': 'proc', 'name': 'proc',
         'logsource': {'product': 'windows', 'category': 'test'},
         'detection': {'s': {'EventID': 1}, 'condition': 's'}},
        {'title': 'burst', 'level': 'high', 'correlation': {
            'type': 'event_count', 'rules': ['proc'], 'group-by': ['Computer'],
            'timespan': '5m', 'condition': {'gte': 2},
        }},
    ]))
    control = run_cli(tmp_path, source, rules, '-c', config, '--timefield', mapped)
    assert control[0]['alert_count'] == 1
    actual = run_cli(tmp_path, source, rules, '-c', config)
    assert sum(rule.get('alert_count', 0) for rule in actual) == 1


@pytest.mark.parametrize('kind', ['json', 'sysmon_json', 'evtx', 'xml', 'evtxtract'])
def test_conventional_timestamp_is_not_remapped_as_a_top_level_field(tmp_path, kind):
    detector = LogTypeDetector()
    if kind == 'json':
        detection = detector._classify_json_event({'Event': {'System': {'EventID': 1}}}, False)
    elif kind == 'sysmon_json':
        detection = detector._classify_json_event({'Event': {'System': {
            'Channel': 'Microsoft-Windows-Sysmon/Operational', 'EventID': 1,
        }}}, False)
    elif kind == 'evtx':
        source = tmp_path / 'events.evtx'
        source.write_bytes(b'ElfFile\x00' + b'\x00' * 8)
        detection = detector.detect(source)
    elif kind == 'xml':
        detection = detector._check_xml('<Event><System><EventID>1</EventID></System></Event>')
    else:
        detection = detector._check_evtxtract('Found at offset 0\nRecord number 1\n<Event><System/></Event>')
    assert detection is not None
    config = write_json(tmp_path / 'config.json', {
        'mappings': {
            'SystemTime': 'Recorded_At', 'UtcTime': 'Recorded_At',
            'Event.System.TimeCreated.#attributes.SystemTime': 'SystemTime',
            'Event.EventData.UtcTime': 'UtcTime',
        },
    })
    args = Namespace(timefield='SystemTime')
    _apply_detection_result(args, detection, logging.getLogger(__name__), json.loads(config.read_text()))
    processor = StreamingEventProcessor(str(config), Namespace(json_input=True))
    flattened = processor._flatten_event({'Event': {
        'System': {'TimeCreated': {'#attributes': {'SystemTime': '2026-01-01T00:00:00Z'}}},
        'EventData': {'UtcTime': '2026-01-01T00:00:00Z'},
    }}, 'source')
    assert args.timefield == ('UtcTime' if kind == 'sysmon_json' else 'SystemTime')
    assert flattened[args.timefield] == '2026-01-01T00:00:00Z'


@pytest.mark.parametrize('event,expected', [
    ({'logged_at': '2026-01-01T00:00:00Z'}, 'Recorded_At'),
    ({'outer': {'logged_at': '2026-01-01T00:00:00Z'}}, 'loggedat'),
    ({'outer': {'logged_at': '2026-01-01T00:00:00Z'},
      'logged_at': 'recorded on 2026-01-01T00:00:00Z'}, 'loggedat'),
])
def test_regex_timestamp_maps_only_a_confirmed_raw_field(tmp_path, event, expected):
    config = write_json(tmp_path / 'config.json', {'mappings': {'logged_at': 'Recorded_At'}})
    source = write_json(tmp_path / 'events.json', event)
    detection = LogTypeDetector().detect(source)
    args = Namespace(timefield='SystemTime')
    _apply_detection_result(args, detection, logging.getLogger(__name__), json.loads(config.read_text()))
    processor = StreamingEventProcessor(str(config), Namespace(json_input=True))
    flattened = processor._flatten_event(event, 'source')
    assert args.timefield == expected
    assert flattened[expected] == '2026-01-01T00:00:00Z'


@pytest.mark.parametrize('event,raw,expected', [
    ({'Channel': 'Security', 'EventID': 1,
      'TimeCreated': {'SystemTime': '2026-01-01T00:00:00Z'}}, 'SystemTime', 'SystemTime'),
    ({'Channel': 'Microsoft-Windows-Sysmon/Operational', 'EventID': 1,
      'EventData': {'UtcTime': '2026-01-01T00:00:00Z'}}, 'UtcTime', 'UtcTime'),
    ({'event': {'module': 'winlogbeat'},
      'outer': {'@timestamp': '2026-01-01T00:00:00Z'}}, '@timestamp', 'timestamp'),
    ({'event': {'module': 'winlogbeat'}, 'winlog': {'channel': 'Security'},
      'outer': {'@timestamp': '2026-01-01T00:00:00Z'}}, '@timestamp', 'timestamp'),
    ({'type': 'SYSCALL', 'outer': {'timestamp': '2026-01-01T00:00:00Z'}}, 'timestamp', 'timestamp'),
])
def test_inferred_json_timestamp_ignores_unrelated_top_level_mapping(tmp_path, event, raw, expected):
    config = write_json(tmp_path / 'config.json', {'mappings': {raw: 'Recorded_At'}})
    source = write_json(tmp_path / 'events.json', event)
    detection = LogTypeDetector().detect(source)
    args = Namespace(timefield='SystemTime')
    _apply_detection_result(args, detection, logging.getLogger(__name__), json.loads(config.read_text()))
    processor = StreamingEventProcessor(str(config), Namespace(json_input=True))
    flattened = processor._flatten_event(event, 'source')
    assert args.timefield == expected
    assert flattened[args.timefield] == '2026-01-01T00:00:00Z'


@pytest.mark.parametrize('backend', ['python', 'auto'])
def test_epoch_zero_obeys_after_bound(tmp_path, backend):
    config = write_json(tmp_path / 'config.json', {})
    processor = StreamingEventProcessor(str(config), Namespace(json_input=True),
        ProcessingConfig(time_field='timestamp', time_after='2026-01-01T00:00:00', flatten_backend=backend))
    assert processor._flatten_event({'timestamp': 1}, 'source') is None
    assert processor._flatten_event({'timestamp': 0}, 'source') is None
    assert processor._flatten_event({'timestamp': '2026-01-01T00:00:00Z'}, 'source') is not None


def test_early_filter_preserves_matches_after_channel_transform(tmp_path):
    config = write_json(tmp_path / 'config.json', {
        'transforms_enabled': True,
        'transforms': {'Channel': [{
            'alias': False, 'source_condition': ['json_input'],
            'code': 'def transform(param):\n    return param.strip()',
        }]},
    })
    source = tmp_path / 'events.jsonl'
    source.write_text(json.dumps({'Channel': ' Security ', 'EventID': 1}) + '\n')
    rules = write_json(tmp_path / 'rules.json', [{
        'title': 'match', 'rule': ["SELECT * FROM logs WHERE Channel='Security' AND EventID=1"],
    }])
    control = run_cli(tmp_path, source, rules, '-c', config, '-j', '--no-event-filter')
    assert control[0]['count'] == 1
    assert control[0]['matches'][0]['Channel'] == 'Security'
    actual = run_cli(tmp_path, source, rules, '-c', config, '-j')
    assert sum(rule['count'] for rule in actual) == 1


@pytest.mark.parametrize('event,config,query', [
    ({'EventID': 1}, {'transforms': {'EventID': [{'alias': False, 'code': 'def transform(param):\n    return 2'}]}},
     'SELECT * FROM logs WHERE EventID=2'),
    ({'Event': {'System': {'Channel': ' Security '}}}, {
        'mappings': {'Event.System.Channel': 'Channel'},
        'transforms': {'Event.System.Channel': [{'alias': False, 'code': 'def transform(param):\n    return param.strip()'}]},
    }, "SELECT * FROM logs WHERE Channel='Security'"),
    ({'Channel': 'Other', 'Source': 'Security'}, {
        'transforms': {'Source': [{'alias': True, 'alias_name': 'Channel', 'code': 'def transform(param):\n    return param'}]},
    }, "SELECT * FROM logs WHERE Channel='Security'"),
    ({'Channel': 'Other', 'Event': {'Source': ' Security '}}, {
        'alias': {'Event.Source': 'Channel'},
        'transforms': {'Source': [{'alias': False, 'code': 'def transform(param):\n    return param.strip()'}]},
    }, "SELECT * FROM logs WHERE Channel='Security'"),
    ({'Channel': 'Other', 'Event.Source': ' Security '}, {
        'alias': {'EventSource': 'Channel'},
        'transforms': {'Event.Source': [{'alias': False, 'code': 'def transform(param):\n    return param.strip()'}]},
    }, "SELECT * FROM logs WHERE Channel='Security'"),
    ({'Channel': 'Other', 'Outer': {'Event.Source': ' Security '}}, {
        'alias': {'EventSource': 'Channel'},
        'transforms': {'Outer.Event.Source': [{'alias': False, 'code': 'def transform(param):\n    return param.strip()'}]},
    }, "SELECT * FROM logs WHERE Channel='Security'"),
    ({'Channel': 'Other', 'Outer': {'Event.Payload': ' Security '}}, {
        'split': {'EventPayload': {'separator': ',', 'equal': '='}},
        'transforms': {'Outer.Event.Payload': [{'alias': False, 'code': 'def transform(param):\n    return "Channel=" + param.strip()'}]},
    }, "SELECT * FROM logs WHERE Channel='Security'"),
    ({'Channel': 'Other', 'Event': {'Payload': ' Security '}}, {
        'split': {'Event.Payload': {'separator': ',', 'equal': '='}},
        'transforms': {'Payload': [{'alias': False, 'code': 'def transform(param):\n    return "Channel=" + param.strip()'}]},
    }, "SELECT * FROM logs WHERE Channel='Security'"),
])
def test_early_filter_preserves_transformed_ids_and_aliases(tmp_path, event, config, query):
    config['transforms_enabled'] = True
    for specs in config['transforms'].values():
        for spec in specs:
            spec['source_condition'] = ['json_input']
    mapping = write_json(tmp_path / 'config.json', config)
    source = tmp_path / 'events.jsonl'
    source.write_text(json.dumps(event) + '\n')
    rules = write_json(tmp_path / 'rules.json', [{'title': 'match', 'rule': [query]}])
    assert run_cli(tmp_path, source, rules, '-c', mapping, '-j', '--no-event-filter')[0]['count'] == 1
    assert sum(rule['count'] for rule in run_cli(tmp_path, source, rules, '-c', mapping, '-j')) == 1


@pytest.mark.parametrize('field,spec,enabled', [
    ('Channel', {'alias': False}, False),
    ('Channel', {'alias': False, 'enabled': False}, True),
    ('Channel', {'alias': False, 'source_condition': ['auditd_input']}, True),
    ('Channel', {'alias': True, 'alias_name': 'ChannelCopy'}, True),
    ('Message', {'alias': False}, True),
])
def test_unrelated_or_inactive_transforms_keep_early_filtering(tmp_path, field, spec, enabled):
    config = write_json(tmp_path / 'config.json', {
        'transforms_enabled': enabled,
        'transforms': {field: [{
            'code': 'def transform(param):\n    return param.strip()',
            'source_condition': ['json_input'], **spec,
        }]},
    })
    source = tmp_path / 'events.jsonl'
    source.write_text('{"Channel":"Other","Message":" text "}\n')
    processor = StreamingEventProcessor(str(config), Namespace(json_input=True), event_filter=EventFilter([
        {'rule': ["SELECT * FROM logs WHERE Channel='Security'"]},
    ]))
    assert list(processor.stream_json_events(str(source))) == []
    assert processor.events_filtered_count == 1

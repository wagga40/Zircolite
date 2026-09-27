"""Review reproductions. Assertions describe expected user-visible behavior."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def run_case(tmp_path, events, query, config=None, options=()):
    source = tmp_path / 'events.jsonl'
    source.write_text(''.join(json.dumps(row) + '\n' for row in events))
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps([{'title': 'test', 'rule': [query]}]))
    mapping = tmp_path / 'mapping.json'
    mapping.write_text(json.dumps(config or {}))
    output = tmp_path / 'results.json'
    completed = subprocess.run([
        sys.executable, str(ROOT / 'zircolite.py'), '-e', str(source),
        '-r', str(rules), '-c', str(mapping), '-o', str(output),
        '-l', str(tmp_path / 'run.log'), '-j', '--quiet', *options,
    ], cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(output.read_text())


@pytest.mark.parametrize('config,event', [
    ({'mappings': {'Source': 'Channel'}}, {'Channel': 'Other', 'Source': 'Security'}),
    ({'alias': {'Source': 'Channel'}}, {'Channel': 'Other', 'Source': 'Security'}),
])
def test_raw_filter_does_not_discard_a_matching_flattened_event(tmp_path, config, event):
    query = "SELECT * FROM logs WHERE Channel='Security'"
    control = run_case(tmp_path, [event], query, config, ('--no-event-filter',))
    assert control[0]['count'] == 1
    actual = run_case(tmp_path, [event], query, config)
    assert sum(rule['count'] for rule in actual) == 1


def test_float_comparison_is_numeric(tmp_path):
    control = run_case(tmp_path, [{'Duration': 0}, {'Duration': 10.5}, {'Duration': 2.5}],
                       'SELECT * FROM logs WHERE Duration > 9')
    assert control[0]['count'] == 1
    actual = run_case(tmp_path, [{'Duration': 10.5}, {'Duration': 2.5}],
                      'SELECT * FROM logs WHERE Duration > 9')
    assert sum(rule['count'] for rule in actual) == 1
    assert float(actual[0]['matches'][0]['Duration']) == 10.5


@pytest.mark.parametrize('backend', ['python', 'auto'])
@pytest.mark.parametrize('config', [{}, {'alias': {'Value': 'ValueCopy'}}])
def test_float_first_column_preserves_later_large_integer(tmp_path, backend, config):
    integer = 9007199254740993
    result = run_case(tmp_path, [{'Value': 0.5}, {'Value': integer}],
                      'SELECT * FROM logs WHERE Value > 1', config,
                      ('--flatten-backend', backend))
    assert result[0]['matches'][0]['Value'] == integer


def test_nested_timestamp_mapping_works_for_auto_correlations(tmp_path):
    import yaml
    source = tmp_path / 'events.jsonl'
    source.write_text(''.join(json.dumps({'Event': {'System': {
        'EventID': 1, 'Computer': 'host',
        'TimeCreated': {'#attributes': {'SystemTime': f'2026-01-01T00:00:0{i}Z'}}
    }}}) + '\n' for i in range(2)))
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'mappings': {
        'Event.System.TimeCreated.#attributes.SystemTime': 'RecordedAt'
    }}))
    rules = tmp_path / 'rules.yml'
    rules.write_text(yaml.safe_dump_all([
        {'title': 'proc', 'name': 'proc', 'logsource': {'product': 'windows', 'category': 'test'},
         'detection': {'s': {'EventID': 1}, 'condition': 's'}},
        {'title': 'burst', 'correlation': {'type': 'event_count', 'rules': ['proc'],
         'group-by': ['Computer'], 'timespan': '5m', 'condition': {'gte': 2}}},
    ]))
    output = tmp_path / 'results.json'
    def run(*options):
        result = subprocess.run([sys.executable, str(ROOT/'zircolite.py'), '-e', str(source),
            '-c', str(config), '-r', str(rules), '-o', str(output), '-l', str(tmp_path/'run.log'),
            '--quiet', *options], cwd=tmp_path, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        return json.loads(output.read_text())
    assert run('--timefield', 'RecordedAt')[0]['alert_count'] == 1
    assert sum(r.get('alert_count', 0) for r in run()) == 1



@pytest.mark.parametrize('backend', ['python', 'auto'])
@pytest.mark.parametrize('kind', ['plain', 'alias', 'transform'])
def test_float_storage_and_comparison_through_all_leaf_paths(tmp_path, backend, kind):
    from argparse import Namespace

    from zircolite import ProcessingConfig, StreamingEventProcessor, ZircoliteCore
    config = {}
    if kind == 'alias':
        config['alias'] = {'Duration': 'DurationCopy'}
    elif kind == 'transform':
        config = {'transforms_enabled': True, 'transforms': {'Source': [{
            'alias': True, 'alias_name': 'Duration', 'source_condition': ['json_input'],
            'code': 'def transform(param):\n    return float(param)',
        }]}}
    mapping = tmp_path / 'mapping.json'
    mapping.write_text(json.dumps(config))
    core = ZircoliteCore(str(mapping), ProcessingConfig(no_output=True))
    try:
        processor = StreamingEventProcessor(str(mapping), Namespace(json_input=True),
            ProcessingConfig(flatten_backend=backend))
        processor.create_initial_table(core.db_connection)
        key = 'Source' if kind == 'transform' else 'Duration'
        rows = [processor._flatten_event({key: value}, 'source') for value in (10.5, 2.5)]
        cursor = core.db_connection.cursor()
        try:
            processor._insert_batch(core.db_connection, cursor, rows)
        finally:
            cursor.close()
        result = core.execute_select_query('SELECT Duration FROM logs WHERE Duration > 9')
        assert result == [{'Duration': 10.5}]
        assert core.execute_select_query('SELECT typeof(Duration) AS t FROM logs LIMIT 1') == [{'t': 'real'}]
    finally:
        core.close()


@pytest.mark.parametrize('kind', ['evtx', 'xml', 'sysmon_json', 'nested_json'])
def test_timestamp_detection_preserves_nested_source_path(tmp_path, kind):
    import logging
    from argparse import Namespace

    from zircolite.cli import _apply_detection_result
    from zircolite.detector import LogTypeDetector
    detector = LogTypeDetector()
    if kind == 'evtx':
        source = tmp_path / 'events.evtx'
        source.write_bytes(b'ElfFile\x00' + b'\x00' * 8)
        detection = detector.detect(source)
        path = 'Event.System.TimeCreated.#attributes.SystemTime'
    elif kind == 'xml':
        detection = detector._check_xml('<Event><System><EventID>1</EventID></System></Event>')
        path = 'Event.System.TimeCreated.#attributes.SystemTime'
    else:
        event = {'Event': {'System': {'Channel': 'Microsoft-Windows-Sysmon/Operational'},
                           'EventData': {'UtcTime': '2026-01-01T00:00:00Z'}}} if kind == 'sysmon_json' else {
            'outer': {'logged_at': '2026-01-01T00:00:00Z'}}
        path = 'Event.EventData.UtcTime' if kind == 'sysmon_json' else 'outer.logged_at'
        source = tmp_path / 'events.json'
        source.write_text(json.dumps(event))
        detection = detector.detect(source)
    args = Namespace(timefield='SystemTime')
    _apply_detection_result(args, detection, logging.getLogger(__name__), {'mappings': {path: 'RecordedAt'}})
    assert args.timefield == 'RecordedAt'


def test_filter_considers_synthesized_metadata_fields(tmp_path):
    event = {'Channel': 'Other'}
    config = {'mappings': {'OriginalLogfile': 'Channel'}}
    query = "SELECT * FROM logs WHERE Channel='events.jsonl'"
    assert run_case(tmp_path, [event], query, config, ('--no-event-filter',))[0]['count'] == 1
    assert sum(r['count'] for r in run_case(tmp_path, [event], query, config)) == 1


@pytest.mark.parametrize('field', ['Data', 'Message'])
@pytest.mark.parametrize('data', [['Security'], {'#text': ['Security']}])
def test_filter_considers_normalized_unnamed_event_data(tmp_path, field, data):
    event = {'Channel': 'Other', 'Event': {'EventData': {'Data': data}}}
    config = {'mappings': {f'Event.EventData.{field}': 'Channel'}}
    query = "SELECT * FROM logs WHERE Channel='Security'"
    assert run_case(tmp_path, [event], query, config, ('--no-event-filter',))[0]['count'] == 1
    assert sum(r['count'] for r in run_case(tmp_path, [event], query, config)) == 1

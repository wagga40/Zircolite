"""
Functional tests for process_unified_streaming, process_parallel_streaming, and process_db_input.

These processing modes were previously only reachability-checked; here we exercise their logic
with real temp files and assert on outputs and context updates.
"""

import json
import sqlite3
import time
from argparse import Namespace

from zircolite.processing import (
    ProcessingContext,
    process_unified_streaming,
    process_parallel_streaming,
    process_db_input,
)
from zircolite.utils import MemoryTracker


def _make_ctx(
    tmp_path,
    field_mappings_file,
    test_logger,
    sample_ruleset,
    *,
    no_output=True,
    outfile=None,
    keepflat=False,
    dbfile=None,
):
    outfile = outfile or str(tmp_path / "detected_events.json")
    return ProcessingContext(
        config=field_mappings_file,
        logger=test_logger,
        no_output=no_output,
        events_after=time.strptime("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
        events_before=time.strptime("9999-12-12T23:59:59", "%Y-%m-%dT%H:%M:%S"),
        limit=-1,
        csv_mode=False,
        time_field="SystemTime",
        hashes=False,
        db_location=":memory:",
        delimiter=";",
        rulesets=sample_ruleset,
        rule_filters=None,
        outfile=outfile,
        ready_for_templating=False,
        package=False,
        dbfile=dbfile,
        keepflat=keepflat,
        memory_tracker=MemoryTracker(logger=test_logger),
    )


def _default_args():
    return Namespace(
        evtx=None,
        select=None,
        avoid=None,
        fileext=None,
        file_pattern=None,
        no_recursion=False,
        archive_password=None,
        after="1970-01-01T00:00:00",
        before="9999-12-12T23:59:59",
        no_event_filter=False,
        json_input=False,
        json_array_input=False,
        db_input=False,
        sysmon_linux_input=False,
        auditd_input=False,
        xml_input=False,
        evtxtract_input=False,
        csv_input=False,
        logs_encoding=None,
        ruleset=[],
        save_ruleset=False,
        pipeline=None,
        pipeline_list=False,
        rulefilter=None,
        test_rules=None,
        outfile="detected_events.json",
        csv=False,
        csv_delimiter=";",
        keepflat=False,
        profile_rules=False,
        dbfile=None,
        logfile="zircolite.log",
        hashes=False,
        limit=-1,
        config="config/config.yaml",
        quiet=False,
        debug=False,
        nolog=True,
        remove_events=False,
        update_rules=False,
        version=False,
        timefield="SystemTime",
        unified_db=False,
        no_auto_mode=False,
        no_auto_detect=False,
        add_index=[],
        remove_index=[],
        all_transforms=False,
        transform_categories=None,
        transform_list=False,
        yaml_config=None,
        generate_config=None,
        no_parallel=False,
        parallel_workers=None,
        parallel_memory_limit=85.0,
        template=None,
        templateOutput=None,
        timesketch=False,
        navigator_output=None,
        package=False,
        package_dir="",
    )


# =============================================================================
# process_unified_streaming
# =============================================================================


class TestProcessUnifiedStreaming:
    """Functional tests for process_unified_streaming."""

    def test_unified_returns_total_events_and_writes_output(
        self,
        field_mappings_file,
        test_logger,
        default_args_config,
        sample_ruleset,
        tmp_path,
    ):
        ev1 = tmp_path / "a.json"
        ev2 = tmp_path / "b.json"
        ev1.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}\n'
        )
        ev2.write_text(
            '{"Event": {"System": {"EventID": 2}, "EventData": {"CommandLine": "cmd.exe"}}}\n'
        )
        outfile = tmp_path / "unified_out.json"
        ctx = _make_ctx(
            tmp_path, field_mappings_file, test_logger, sample_ruleset, outfile=str(outfile)
        )
        ctx.no_output = False

        core, results = process_unified_streaming(
            ctx, [ev1, ev2], "json", None, default_args_config
        )
        core.close()

        assert ctx.total_events == 2
        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert isinstance(data, list)
        assert len(results) >= 1
        assert any(r.get("title") == "Suspicious PowerShell Command" for r in results)

    def test_unified_single_file_same_as_perfile_count(
        self,
        field_mappings_file,
        test_logger,
        default_args_config,
        sample_ruleset,
        tmp_path,
    ):
        jf = tmp_path / "single.json"
        jf.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}\n'
        )
        ctx = _make_ctx(tmp_path, field_mappings_file, test_logger, sample_ruleset)
        core, results = process_unified_streaming(ctx, [jf], "json", None, default_args_config)
        core.close()
        assert ctx.total_events == 1
        assert len(results) >= 1


# =============================================================================
# process_parallel_streaming
# =============================================================================


class TestProcessParallelStreaming:
    """Functional tests for process_parallel_streaming."""

    def test_parallel_two_files_merges_results_and_sets_workers_used(
        self,
        field_mappings_file,
        test_logger,
        default_args_config,
        sample_ruleset,
        tmp_path,
    ):
        a = tmp_path / "f1.json"
        b = tmp_path / "f2.json"
        a.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}\n'
        )
        b.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe -c x"}}}\n'
        )
        outfile = tmp_path / "parallel_out.json"
        ctx = _make_ctx(
            tmp_path, field_mappings_file, test_logger, sample_ruleset, outfile=str(outfile)
        )
        ctx.no_output = False
        default_args_config.parallel_workers = None

        _, results = process_parallel_streaming(
            ctx, [a, b], "json", None, default_args_config, recommended_workers=2
        )

        assert ctx.total_events == 2
        assert ctx.workers_used >= 1
        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert isinstance(data, list)
        assert len(results) >= 1
        assert ctx.file_stats is not None
        assert len(ctx.file_stats) == 2

    def test_parallel_single_file_falls_back_to_perfile(
        self,
        field_mappings_file,
        test_logger,
        default_args_config,
        sample_ruleset,
        tmp_path,
    ):
        jf = tmp_path / "one.json"
        jf.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "whoami"}}}\n'
        )
        ctx = _make_ctx(tmp_path, field_mappings_file, test_logger, sample_ruleset)
        _, results = process_parallel_streaming(ctx, [jf], "json", None, default_args_config)
        assert ctx.total_events == 1
        assert len(results) >= 1


# =============================================================================
# process_db_input
# =============================================================================


class TestProcessDbInput:
    """Functional tests for process_db_input."""

    def test_db_input_executes_rules_against_loaded_db(
        self,
        field_mappings_file,
        test_logger,
        default_args_config,
        sample_ruleset,
        tmp_path,
    ):
        db_path = tmp_path / "input.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            """
            CREATE TABLE logs (
                row_id INTEGER PRIMARY KEY,
                EventID TEXT,
                Channel TEXT,
                Computer TEXT,
                CommandLine TEXT,
                Image TEXT,
                User TEXT,
                SystemTime TEXT,
                TargetFileName TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO logs (EventID, CommandLine, SystemTime) VALUES (?, ?, ?)",
            ("1", "powershell.exe -encodedCommand x", "2024-01-15T10:30:00"),
        )
        conn.commit()
        conn.close()

        outfile = tmp_path / "db_detected.json"
        ctx = _make_ctx(
            tmp_path, field_mappings_file, test_logger, sample_ruleset, outfile=str(outfile)
        )
        ctx.no_output = False
        args = _default_args()
        args.evtx = str(db_path)

        core, results = process_db_input(ctx, args)
        core.close()

        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert isinstance(data, list)
        assert any(r.get("title") == "Suspicious PowerShell Command" for r in results)

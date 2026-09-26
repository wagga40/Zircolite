"""Tests for graceful shutdown coordination (Ctrl+C handling)."""

import json
import os
import signal
import sys
import time
from argparse import Namespace
from pathlib import Path

import pytest

from zircolite import shutdown
from zircolite.parallel import MemoryAwareParallelProcessor, ParallelConfig
from zircolite.processing import ProcessingContext, process_perfile_streaming
from zircolite.utils import MemoryTracker


@pytest.fixture(autouse=True)
def _reset_shutdown_state():
    shutdown.reset_shutdown_state()
    yield
    shutdown.reset_shutdown_state()


class TestShutdownEvent:
    def test_initial_state_is_clear(self):
        assert shutdown.is_shutdown_requested() is False

    def test_request_shutdown_sets_flag(self):
        shutdown.request_shutdown()
        assert shutdown.is_shutdown_requested() is True

    def test_reset_clears_flag(self):
        shutdown.request_shutdown()
        assert shutdown.is_shutdown_requested() is True
        shutdown.reset_shutdown_state()
        assert shutdown.is_shutdown_requested() is False


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only signal semantics")
class TestSignalHandler:
    def test_install_replaces_default_handler(self):
        previous = signal.getsignal(signal.SIGINT)
        try:
            shutdown.install_signal_handler()
            installed = signal.getsignal(signal.SIGINT)
            assert installed is shutdown._sigint_handler
        finally:
            signal.signal(signal.SIGINT, previous)

    def test_first_sigint_sets_flag_without_raising(self, capsys):
        previous = signal.getsignal(signal.SIGINT)
        try:
            shutdown.install_signal_handler()
            shutdown._sigint_handler(signal.SIGINT, None)
            assert shutdown.is_shutdown_requested() is True
            captured = capsys.readouterr()
            assert "Interrupt received" in captured.err
            assert "Press Ctrl+C again" in captured.err
        finally:
            signal.signal(signal.SIGINT, previous)

    def test_second_sigint_raises_keyboard_interrupt(self):
        previous = signal.getsignal(signal.SIGINT)
        try:
            shutdown.install_signal_handler()
            shutdown._sigint_handler(signal.SIGINT, None)
            with pytest.raises(KeyboardInterrupt):
                shutdown._sigint_handler(signal.SIGINT, None)
        finally:
            signal.signal(signal.SIGINT, previous)


def _ctrl_c_during_start_up():
    # Stands in for a Ctrl+C that reaches a worker still importing Zircolite,
    # before any initializer has had the chance to ignore SIGINT.
    os.kill(os.getpid(), signal.SIGINT)


def _sigint_held(_path):
    return 0, signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, [])


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only signal semantics")
class TestWorkerStartUp:
    """A terminal Ctrl+C reaches the workers too, including ones still starting.

    One Ctrl+C during process-pool start-up used to raise KeyboardInterrupt in
    every starting worker: the pool broke and each file in flight was reported
    as "terminated abruptly", although the parent had promised to finish them.
    """

    def _run(self, tmp_path, executor, initializer=None):
        source = tmp_path / "events.jsonl"
        source.write_text("{}\n")
        processor = MemoryAwareParallelProcessor(ParallelConfig(max_workers=1, executor=executor))
        return processor.process_files_parallel(
            [source], _sigint_held, disable_progress=True, initializer=initializer)

    def test_ctrl_c_before_the_initializer_does_not_break_the_pool(self, tmp_path):
        results, stats = self._run(tmp_path, "process", initializer=_ctrl_c_during_start_up)
        assert stats.failed_files == []
        assert results == [True]

    def test_parent_signal_state_is_restored(self, tmp_path):
        handler = signal.getsignal(signal.SIGINT)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        self._run(tmp_path, "process")
        assert signal.getsignal(signal.SIGINT) is handler
        assert signal.pthread_sigmask(signal.SIG_BLOCK, []) == mask

    def test_thread_workers_are_left_alone(self, tmp_path):
        results, _ = self._run(tmp_path, "thread")
        assert results == [False]


class TestLoopsObserveShutdown:
    """The flag is only useful if the long-running loops actually check it.

    Nothing asserted that before, which is how an interrupted --remove-events
    run came to delete files it had never opened.
    """

    def _context(self, tmp_path, field_mappings_file, test_logger, sample_ruleset):
        return ProcessingContext(
            config=field_mappings_file,
            logger=test_logger,
            no_output=True,
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
            outfile=str(tmp_path / "detected_events.json"),
            ready_for_templating=False,
            package=False,
            dbfile=None,
            keepflat=False,
            memory_tracker=MemoryTracker(logger=test_logger),
        )

    def test_perfile_loop_reads_nothing_once_shutdown_is_requested(
        self, tmp_path, field_mappings_file, test_logger, sample_ruleset
    ):
        files = []
        for index in range(3):
            path = tmp_path / f"events{index}.json"
            path.write_text(json.dumps(
                {"Event": {"System": {"EventID": 1}, "EventData": {}}}
            ))
            files.append(Path(path))

        ctx = self._context(tmp_path, field_mappings_file, test_logger, sample_ruleset)
        args = Namespace(json_input=True, keepflat=False, limit=-1)

        shutdown.request_shutdown()
        process_perfile_streaming(ctx, files, "json", None, args)

        assert ctx.total_events == 0, (
            "The per-file loop must stop at its checkpoint, leaving later files unread"
        )

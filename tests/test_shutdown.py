"""Tests for graceful shutdown coordination (Ctrl+C handling)."""

import signal
import sys

import pytest

from zircolite import shutdown


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

    def test_event_object_is_settable_and_observable(self):
        evt = shutdown.shutdown_event()
        assert evt.is_set() is False
        evt.set()
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

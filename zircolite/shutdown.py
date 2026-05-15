"""Graceful shutdown coordination for Zircolite (Ctrl+C handling).

A single module-level ``threading.Event`` is set by the SIGINT handler so that
long-running loops in the parallel processor, the streaming event consumer, and
the rule executor can observe the request at safe checkpoints. A second Ctrl+C
restores the default handler so Python exits immediately with status 130.
"""

import signal
import sys
import threading

_shutdown_event = threading.Event()
_force_quit_armed = False


def is_shutdown_requested() -> bool:
    return _shutdown_event.is_set()


def shutdown_event() -> threading.Event:
    return _shutdown_event


def request_shutdown() -> None:
    _shutdown_event.set()


def reset_shutdown_state() -> None:
    """Reset shutdown state. Intended for use by tests only."""
    global _force_quit_armed
    _shutdown_event.clear()
    _force_quit_armed = False


def _sigint_handler(signum, frame):
    global _force_quit_armed
    if _force_quit_armed:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        raise KeyboardInterrupt
    _force_quit_armed = True
    _shutdown_event.set()
    sys.stderr.write(
        "\n[!] Interrupt received - finishing current work and shutting down. "
        "Press Ctrl+C again to force quit.\n"
    )
    sys.stderr.flush()


def install_signal_handler() -> None:
    signal.signal(signal.SIGINT, _sigint_handler)

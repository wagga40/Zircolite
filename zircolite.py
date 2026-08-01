#!python3
"""Zircolite entry point.

The CLI itself lives in ``zircolite/cli.py``. This file stays empty on purpose:
it shares its name with the ``zircolite`` package, so ``mypy`` cannot be pointed
at both, and anything defined here would go unchecked. ``tests/test_entry_point.py``
is what keeps it that way.
"""

from zircolite.cli import main

if __name__ == "__main__":
    main()

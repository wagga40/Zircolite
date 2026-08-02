"""Support ``python -m zircolite``.

Nothing in the package imports this module, which is what keeps it clear of the
import cycle that re-exporting the CLI from ``__init__.py`` would create.
"""

from zircolite.cli import main

if __name__ == "__main__":
    main()

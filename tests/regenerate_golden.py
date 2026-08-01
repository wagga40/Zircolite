#!/usr/bin/env python3
"""Rewrite the golden detection files under tests/golden/.

Run this only when a change is *meant* to alter which events match, and read
the resulting diff before committing it -- that diff is the whole point of the
golden files.

    pdm run python tests/regenerate_golden.py
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).parent.parent
GOLDEN = Path(__file__).parent / "golden"

sys.path.insert(0, str(WORKSPACE_ROOT))

from tests.test_e2e_regression import (  # noqa: E402
    FIXTURES,
    TestGoldenDetections,
    detection_summary,
)


def main() -> int:
    GOLDEN.mkdir(exist_ok=True)
    for name, filename, flags, ruleset in TestGoldenDetections.CASES:
        tmp = Path(tempfile.mkdtemp(prefix="zircolite_golden_"))
        try:
            outfile = tmp / "detected.json"
            subprocess.run(
                [
                    sys.executable, str(WORKSPACE_ROOT / "zircolite.py"),
                    "-e", str(FIXTURES / filename),
                    "-r", str(WORKSPACE_ROOT / "rules" / ruleset),
                    "-o", str(outfile),
                    "-l", str(tmp / "zircolite.log"),
                    *flags,
                ],
                check=True,
                cwd=str(WORKSPACE_ROOT),
                capture_output=True,
            )
            summary = detection_summary(json.loads(outfile.read_text()))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        target = GOLDEN / f"{name}.json"
        target.write_text(json.dumps(summary, indent=2) + "\n")
        print(f"{target.relative_to(WORKSPACE_ROOT)}: {len(summary)} rule(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

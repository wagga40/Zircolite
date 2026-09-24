"""auditd key=value parsing stays linear in the line length.

The key part of ``_AUDITD_ATTR_RE`` used to be retried from every character
of a run of key characters that has no '=' after it, which is quadratic: one
forged 8 KB audit.log line cost about a second of CPU, and a 1 MB line hours.
The lookbehind added to it only skips starts that could never match, so the
pairs found must be exactly the ones the previous pattern found.
"""

import random
import re
import time
from pathlib import Path

from zircolite.extractor import _AUDITD_ATTR_RE

PREVIOUS = re.compile(r"([\w\[\].]+)=(\"[^\"]*\"|'[^']*'|\S*)")
SAMPLE = Path(__file__).parent / "fixtures" / "audit_sample.log"


def _pairs(pattern, line):
    return [(m.span(), m.group(1), m.group(2)) for m in pattern.finditer(line)]


def test_same_pairs_on_the_sample_log():
    lines = SAMPLE.read_text().splitlines()
    assert lines
    for line in lines:
        assert _pairs(_AUDITD_ATTR_RE, line) == _pairs(PREVIOUS, line)


def test_same_pairs_on_generated_lines():
    rng = random.Random(1)  # noqa: S311 -- reproducible test data
    pieces = ["a", "b1", "_", ".", "[", "]", "=", "==", '"', "'", " ", "  ", "\t",
              "é", "-", ":", "(", ")", "msg=audit(1.2:3):", "key=", "x=\"a b\"", "y='c d'"]
    for _ in range(20000):
        line = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 14)))
        assert _pairs(_AUDITD_ATTR_RE, line) == _pairs(PREVIOUS, line), line


def test_long_run_without_equals_is_linear():
    line = "type=SYSCALL msg=audit(1.1:1): " + "a" * 262144
    started = time.process_time()
    pairs = _pairs(_AUDITD_ATTR_RE, line)
    spent = time.process_time() - started
    assert [p[1] for p in pairs] == ["type", "msg"]
    # The previous pattern needed about a second at 8 KB and grows with the
    # square of the length, so 256 KB would take minutes.
    assert spent < 1.0, f"{spent:.2f}s CPU on a {len(line)}-char line"

"""Conservative literal candidates for SQLite LIKE and text equality.

This is an accelerator, never an evaluator. Every returned candidate still
passes the original WHERE clause. None denotes the universe of rows, so an
unknown predicate cannot accidentally narrow a rule.
"""

import re
import sqlite3
import sys
from collections import OrderedDict, defaultdict
from contextlib import closing
from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Any

import ahocorasick
import orjson
from pyroaring import BitMap64

from .shutdown import is_shutdown_requested
from .sqlscan import (
    _unquote,
    _Unsupported,
    admitted_pairs,
    census_collations_supported,
    iter_tokens,
    normalize_rule_sql,
    rebalance_sql,
)

_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def _fold_ascii(value: str) -> str:
    """``value.translate(_ASCII_FOLD)``, fast enough to run on every scanned value.

    translate() looks each character up one by one once a string holds any
    non-ASCII character, so long PowerShell script blocks would dominate the
    scan. bytes.lower() folds ASCII letters only, and UTF-8 encodes every other
    character as bytes outside that range.
    """
    if value.isascii():
        return value.lower()
    return value.encode("utf-8", "surrogatepass").lower().decode("utf-8", "surrogatepass")


AUTO_MIN_ROWS = 1000
AUTO_MIN_QUERIES = 32
# Share of the rows a rule's Channel/EventID bounds select past which the
# candidates narrow its scan too little to repay handing them over. Measured
# insensitive between 0.25 and 1.0 on the test corpus; a third of a partition still won.
BROAD_FRACTION = 0.5
# What a rule no row can match runs instead of its own SQL.
NO_ROWS = "SELECT 1 WHERE 0"
_UNSUPPORTED_WORDS = frozenset((
    "SELECT", "FROM", "WHERE", "JOIN", "UNION", "INTERSECT", "EXCEPT", "ORDER",
    "GROUP", "HAVING", "LIMIT", "OFFSET", "WINDOW", "CASE", "WHEN", "THEN",
    "ELSE", "END", "BETWEEN", "OVER", "FILTER", "GLOB", "MATCH",
    # Always keywords, even where a column carries the same name.
    "CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME",
))


def _literal(pattern, escape):
    if "\x00" in pattern or (escape is not None and (len(escape) != 1 or escape == "\x00")):
        return None
    runs, run = [], []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == escape:
            i += 1
            if i == len(pattern):
                return None
            run.append(pattern[i])
        elif char in ("%", "_"):
            runs.append("".join(run))
            run = []
        else:
            run.append(char)
        i += 1
    runs.append("".join(run))
    best = max(runs, key=lambda candidate: (_selective(candidate), len(candidate)))
    return best.translate(_ASCII_FOLD) if _selective(best) else None


def _selective(run):
    # Short ASCII runs cost more to index than they eliminate. Any non-ASCII
    # character is rare in logs, and LIKE compares it exactly.
    return len(run) >= 3 or not run.isascii()


# Two-character escapes that match something other than themselves. Any other
# letter or digit after a backslash starts syntax not modelled here.
_REGEX_CLASS_ESCAPES = frozenset("dDwWsSbBAZtnrfv")
# Under IGNORECASE the regex module also matches these letters to U+0130,
# U+212A and U+017F, which ASCII folding of the value would not find.
_UNICODE_CASED = frozenset("iksIKS")
_QUANTIFIER_BRACE = re.compile(r"\{(\d*)(?:,(\d*))?\}")


class _Unbounded(Exception):
    """The pattern uses syntax this reader does not model."""


def _regex_runs(pattern, start, stop):
    """Literal runs every match of ``pattern[start:stop]`` must contain, or raise."""
    runs, run = [], []
    i = start
    last_literal = False
    while i < stop:
        char = pattern[i]
        if char == "\\":
            if i + 1 >= stop:
                raise _Unbounded("trailing escape")
            nxt = pattern[i + 1]
            i += 2
            if nxt.isascii() and not nxt.isalnum():
                run.append(nxt)
                last_literal = True
                continue
            if nxt not in _REGEX_CLASS_ESCAPES:
                raise _Unbounded("escape")
            runs.append("".join(run))
            run, last_literal = [], False
            continue
        if char == "[":
            j = i + 1
            if j < stop and pattern[j] == "^":
                j += 1
            if j < stop and pattern[j] == "]":
                j += 1
            while j < stop and pattern[j] != "]":
                if pattern[j] == "[":
                    raise _Unbounded("nested or POSIX class")
                j += 2 if pattern[j] == "\\" else 1
            if j >= stop:
                raise _Unbounded("unterminated class")
            i = j + 1
            runs.append("".join(run))
            run, last_literal = [], False
            continue
        if char == "(":
            depth, j = 1, i + 1
            while j < stop and depth:
                if pattern[j] == "\\":
                    j += 2
                    continue
                if pattern[j] == "[":
                    # A class may hold parentheses; skip it whole.
                    k = j + 1
                    if k < stop and pattern[k] == "^":
                        k += 1
                    if k < stop and pattern[k] == "]":
                        k += 1
                    while k < stop and pattern[k] != "]":
                        k += 2 if pattern[k] == "\\" else 1
                    j = k + 1
                    continue
                depth += {"(": 1, ")": -1}.get(pattern[j], 0)
                j += 1
            if depth:
                raise _Unbounded("unbalanced group")
            i = j
            runs.append("".join(run))
            run, last_literal = [], False
            continue
        if char in "*+?{":
            minimum = 1
            if char == "{":
                match = _QUANTIFIER_BRACE.match(pattern, i, stop)
                if match is None:
                    raise _Unbounded("brace")
                minimum = int(match.group(1) or 0)
                i = match.end()
            else:
                minimum = 0 if char in "*?" else 1
                i += 1
            if i < stop and pattern[i] in "?+":
                i += 1
            if last_literal and run:
                kept = run[:-1] if minimum == 0 else run
                runs.append("".join(kept))
                run = []
            last_literal = False
            continue
        if char in ".^$":
            runs.append("".join(run))
            run, last_literal = [], False
            i += 1
            continue
        if char in ")|":
            raise _Unbounded("stray")
        run.append(char)
        last_literal = True
        i += 1
    runs.append("".join(run))
    return runs


def _regex_branches(pattern):
    """Split ``pattern`` at its top-level alternations, as (start, stop) pairs."""
    branches, depth, start, i = [], 0, 0, 0
    in_class = False
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            i += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
            if pattern[i + 1:i + 2] == "^":
                i += 1
            if pattern[i + 1:i + 2] == "]":
                i += 1
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            branches.append((start, i))
            start = i + 1
        i += 1
    branches.append((start, len(pattern)))
    return branches


def _regex_expression(column, pattern):
    """A necessary-literal bound for ``column REGEXP pattern``, or None.

    Conservative by construction: only syntax read here can contribute, and a
    branch without a literal of its own leaves the whole pattern unbounded.
    """
    if "\x00" in pattern or len(pattern) > 4096:
        return None
    caseless = False
    for flags in re.findall(r"\(\?([a-zA-Z]+)[:)]", pattern):
        if set(flags) - set("ims"):
            return None
        caseless = caseless or "i" in flags
    try:
        leaves = []
        for start, stop in _regex_branches(pattern):
            runs = _regex_runs(pattern, start, stop)
            if caseless:
                runs = [part for run in runs
                        for part in re.split(r"[iksIKS]|[^\x00-\x7f]", run)]
            best = max(runs, key=lambda candidate: (_selective(candidate), len(candidate)))
            if not _selective(best):
                return None
            leaves.append(("literal", (column, best.translate(_ASCII_FOLD))))
    except _Unbounded:
        return None
    return _combine("or", leaves)


def _posting_budget(rows):
    """Row IDs the index may retain: enough for dense literals on large tables."""
    return max(2_000_000, 16 * rows)


def _combine(operator, nodes):
    if operator == "or" and any(node is None for node in nodes):
        return None
    bounded = tuple(node for node in nodes if node is not None)
    return None if not bounded else bounded[0] if len(bounded) == 1 else (operator, bounded)


class _Reader:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ("end", "")

    def read_or(self):
        nodes = [self.read_and()]
        while self.peek() == ("word", "OR"):
            self.pos += 1
            nodes.append(self.read_and())
        return _combine("or", nodes)

    def read_and(self):
        nodes = [self.primary()]
        while self.peek() == ("word", "AND"):
            self.pos += 1
            nodes.append(self.primary())
        return _combine("and", nodes)

    def primary(self):
        if self.peek() == ("word", "NOT"):
            self.pos += 1
            if self.peek() == ("word", "COALESCE"):
                # normalize_rule_sql's NOT COALESCE((group), 0): the group is
                # read like any other; a negation never narrows the candidates.
                self.pos += 1
                if self.peek() != ("punct", "("):
                    raise _Unsupported("COALESCE")
                self.pos += 1
                self.primary()
                if self.tokens[self.pos:self.pos + 3] != [("punct", ","), ("number", "0"), ("punct", ")")]:
                    raise _Unsupported("COALESCE")
                self.pos += 3
                return None
            self.primary()
            return None
        if self.peek() == ("punct", "("):
            self.pos += 1
            node = self.read_or()
            if self.peek() != ("punct", ")"):
                raise _Unsupported("parentheses")
            self.pos += 1
            return node
        start, depth = self.pos, 0
        while self.pos < len(self.tokens):
            token = self.peek()
            if depth == 0 and token in (("word", "AND"), ("word", "OR"), ("punct", ")")):
                break
            if token == ("punct", "("):
                depth += 1
            elif token == ("punct", ")"):
                depth -= 1
            self.pos += 1
        atom = self.tokens[start:self.pos]
        if not atom or depth:
            raise _Unsupported("atom")
        if ("word", "LIKE") in atom and not (
            len(atom) in (3, 5) and atom[0][0] in ("word", "name")
            and atom[1] == ("word", "LIKE") and atom[2][0] == "literal"
        ):
            raise _Unsupported("complex LIKE")
        if len(atom) not in (3, 5) or atom[0][0] not in ("word", "name"):
            return None
        if atom[1] == ("punct", "=") and atom[2][0] == "literal":
            if len(atom) == 5 and atom[3:] != [("word", "COLLATE"), ("word", "NOCASE")]:
                return None
            value = atom[2][1]
            if "\x00" in value or len(value) > 4096 or not _selective(value):
                return None
            # Keep affinity-dependent predicates distinct in the shared syntax
            # cache. Only a per-database binding can turn them into literals.
            return ("equality", (atom[0][1].translate(_ASCII_FOLD), value.translate(_ASCII_FOLD)))
        if atom[1] == ("word", "REGEXP") and atom[2][0] == "literal" and len(atom) == 3:
            return _regex_expression(atom[0][1].translate(_ASCII_FOLD), atom[2][1])
        if atom[1] != ("word", "LIKE") or atom[2][0] != "literal":
            return None
        if len(atom[2][1].encode("utf-8")) > 4096:
            raise _Unsupported("long LIKE pattern")
        escape = None
        if len(atom) == 5:
            if atom[3] != ("word", "ESCAPE") or atom[4][0] != "literal":
                raise _Unsupported("complex LIKE escape")
            escape = atom[4][1]
            if len(escape) != 1 or escape == "\x00":
                raise _Unsupported("invalid LIKE escape")
        literal = _literal(atom[2][1], escape)
        return None if literal is None else ("literal", (atom[0][1].translate(_ASCII_FOLD), literal))


@dataclass(frozen=True)
class LiteralPlan:
    sql: str
    where_start: int
    expression: Any
    # SQLite rejects a LIKE pattern past SQLITE_LIMIT_LIKE_PATTERN_LENGTH.
    max_literal_bytes: int = 0


def _parse_literal_plan(sql):
    try:
        tokens, ends = [], []
        longest = 0
        for kind, start, end in iter_tokens(sql):
            value = sql[start:end]
            if kind == "comment":
                return None
            if value.isspace():
                continue
            if kind == "literal":
                value = value[1:-1].replace("''", "'")
                longest = max(longest, len(value.encode("utf-8")))
            elif kind == "identifier":
                kind, value = "name", _unquote(value)
            elif kind == "word":
                value = value.translate(_ASCII_UPPER)
            tokens.append((kind, value))
            ends.append(end)
        if tokens and tokens[-1] == ("punct", ";"):
            tokens.pop()
            sql = sql[:ends[-1] - 1].rstrip()
        if len(tokens) < 6 or tokens[:3] != [("word", "SELECT"), ("punct", "*"), ("word", "FROM")]:
            return None
        if tokens[3][0] not in ("word", "name") or tokens[3][1].translate(_ASCII_FOLD) != "logs":
            return None
        if tokens[4] != ("word", "WHERE"):
            return None
        body = tokens[5:]
        for i, (kind, value) in enumerate(body):
            if kind == "word" and value in _UNSUPPORTED_WORDS:
                return None
            # Every logs column is declared NOCASE, so an explicit NOCASE on an
            # equality changes nothing; the reader rejects it after a LIKE.
            if (kind, value) == ("word", "COLLATE") and body[i + 1:i + 2] != [("word", "NOCASE")]:
                return None
            if kind == "punct" and value in (";", "?", ":", "@", "$", "."):
                return None
            # A REGEXP bounds nothing, but its AND siblings still can. Its pattern
            # must be a literal: _uncompilable_regex checks those before the rule
            # runs, so the function cannot raise on a row the candidates skip.
            if (kind, value) == ("word", "REGEXP") and body[i + 1:i + 2] != [] and body[i + 1][0] != "literal":
                return None
            # JSON operators can raise on rows the candidate set would skip.
            if (kind, value) == ("punct", "-") and body[i + 1:i + 2] == [("punct", ">")]:
                return None
            # Function calls may change error behavior when rows are skipped.
            # COALESCE directly under NOT is normalize_rule_sql's wrapper, and
            # cannot raise.
            if kind in ("word", "name") and body[i + 1:i + 2] == [("punct", "(")] and not (
                kind == "word" and (value in ("IN", "NOT", "AND", "OR")
                                    or (value == "COALESCE" and body[i - 1:i] == [("word", "NOT")]))
            ):
                return None
        reader = _Reader(body)
        expression = reader.read_or()
        if reader.pos != len(body) or expression is None:
            return None
        return LiteralPlan(sql, ends[4], expression, longest)
    except (_Unsupported, RecursionError):
        return None


# Plans depend on the SQL text alone, so every file and worker shares them.
_PLANS: dict[str, "LiteralPlan | None"] = {}
# Plans read back from the analysis cache, still as JSON: most rules of a run
# never reach the filter, so they are decoded when first asked for.
_PENDING_PLANS: dict[str, bytes] = {}


def _plan_for(sql):
    try:
        return _PLANS[sql]
    except KeyError:
        pass
    raw = _PENDING_PLANS.pop(sql, None)
    plan = None
    if raw is not None:
        try:
            plan = plan_from_json(orjson.loads(raw), sql)
        except (ValueError, TypeError, KeyError, IndexError):
            raw = None
    if raw is None:
        plan = _parse_literal_plan(sql.strip())
    _PLANS[sql] = plan
    return plan


def plan_to_json(plan: "LiteralPlan", text: str) -> list[Any]:
    """``plan`` as JSON, its SQL omitted when it is ``text`` itself."""
    return [None if plan.sql == text else plan.sql, plan.where_start,
            _expression_to_json(plan.expression), plan.max_literal_bytes]


def plan_from_json(data: Any, text: str) -> "LiteralPlan":
    """The inverse of ``plan_to_json``, refusing anything it would not write."""
    sql, where_start, expression, longest = data
    sql = text if sql is None else sql
    if not isinstance(sql, str) or type(where_start) is not int or type(longest) is not int:
        raise ValueError("bad plan")
    if not 0 <= where_start <= len(sql):
        raise ValueError("bad plan offset")
    return LiteralPlan(sql, where_start, _expression_from_json(expression), longest)


def _expression_to_json(expression: Any) -> Any:
    kind, value = expression
    if kind in ("literal", "equality"):
        return [kind, list(value)]
    return [kind, [_expression_to_json(node) for node in value]]


def _expression_from_json(data: Any) -> Any:
    kind, value = data
    if kind in ("literal", "equality"):
        column, literal = value
        if not isinstance(column, str) or not isinstance(literal, str):
            raise ValueError("bad leaf")
        return (kind, (sys.intern(column), literal))
    if kind not in ("and", "or") or not isinstance(value, list) or len(value) < 2:
        raise ValueError("bad expression")
    return (kind, tuple(_expression_from_json(node) for node in value))


def _leaves(expression):
    if expression[0] == "literal":
        yield expression[1]
    else:
        for node in expression[1]:
            yield from _leaves(node)


def _bind_equalities(expression: Any, text_columns: set[str]) -> Any:
    """Use equality's necessary substring only where SQLite compares text.

    Numeric affinity can equate '001' with 1. Unsupported equality therefore
    means universe, including in OR branches, rather than an empty posting.
    """
    kind, value = expression
    if kind == "literal":
        return expression
    if kind == "equality":
        return ("literal", value) if value[0] in text_columns else None
    return _combine(kind, tuple(_bind_equalities(node, text_columns) for node in value))


def _bind_plan(plan: LiteralPlan, text_columns: set[str], known: dict[str, str]) -> LiteralPlan | None:
    """``plan`` bound to this table, or None if no column here can bound it."""
    expression = _bind_equalities(plan.expression, text_columns)
    if expression is None or any(column not in known for column, _ in _leaves(expression)):
        return None
    return replace(plan, expression=expression)


class _ValueMatches:
    """One automaton's LRU; byte shares sum to the build's total cache budget."""

    def __init__(self, automaton: Any, max_bytes: int) -> None:
        self.automaton = automaton
        self.max_bytes = max_bytes
        self.bytes = 0
        self.values: OrderedDict[str, tuple[tuple[str, ...], int]] = OrderedDict()

    def matches(self, value: str) -> tuple[str, ...]:
        cacheable = len(value) <= 1024 and self.max_bytes > 0
        if cacheable and value in self.values:
            self.values.move_to_end(value)
            return self.values[value][0]
        matched = tuple({literal for _, literal in self.automaton.iter(_fold_ascii(value))})
        if cacheable:
            # Literal strings already belong to the automaton. Count the value,
            # references and a conservative allowance for dict/LRU bookkeeping.
            size = sys.getsizeof(value) + sys.getsizeof(matched) + 256
            if size <= self.max_bytes:
                while self.values and (len(self.values) >= 512 or self.bytes + size > self.max_bytes):
                    _, (_, removed) = self.values.popitem(last=False)
                    self.bytes -= removed
                self.values[value] = (matched, size)
                self.bytes += size
        return matched


def _evaluate(expression, postings, uncertain=None):
    if expression[0] == "literal":
        found = postings.get(expression[1])
        if found is None:
            return None
        extra = (uncertain or {}).get(expression[1][0])
        return found | extra if extra else found
    result = None
    for node in expression[1]:
        other = _evaluate(node, postings, uncertain)
        if other is None:
            if expression[0] == "or":
                return None
            continue
        if result is None:
            result = other.copy()
        elif expression[0] == "and":
            result &= other
        else:
            result |= other
    return result


@dataclass(frozen=True)
class PreparedRules:
    normalized: dict[str, str]


def rule_queries(rules):
    """Prepare SQL only; leave malformed rule values to the existing evaluator.

    A correlation plan never runs its ``rule`` SQL, so there is nothing to prepare.
    """
    return tuple(query for rule in rules
                 if isinstance(rule.get("rule"), (list, tuple)) and rule.get("correlation_plan") is None
                 for query in rule["rule"] if isinstance(query, str))


@lru_cache(maxsize=8)
def prepare_rules(queries):
    """Share immutable SQL normalization across files; never cache database state."""
    return PreparedRules({sql: normalize_rule_sql(sql) for sql in queries})


def clear_prepared_rules():
    prepare_rules.cache_clear()
    _PLANS.clear()
    _PENDING_PLANS.clear()


class LiteralPrefilter:
    """One bounded candidate index for one ruleset execution over stable logs."""

    def __init__(self, connection, rules, *, automatic=False, automaton_factory=None, bitmap_factory=None,
                 max_postings=None, max_pattern_chars=1_000_000, prepared=None, census=None,
                 max_cache_bytes=8 * 1024 * 1024):
        self.connection = connection
        self.plans: dict[str, LiteralPlan] = {}
        self.postings: dict[tuple[str, str], Any] = {}
        self.uncertain: dict[str, Any] = {}
        self.skipped_columns: dict[str, str] = {}
        self.eligible_queries = 0
        self.broad_bypasses = 0
        self.unbounded_bypasses = 0
        self.prepared = prepared
        self.census = census
        self._partition_rows: dict[str, int] = {}
        self.reason = None
        self.accelerated = 0
        self.total_rows = 0
        self.automaton_factory = automaton_factory or ahocorasick.Automaton
        self.bitmap_factory = bitmap_factory or BitMap64
        try:
            if automatic and len(rule_queries(rules)) < AUTO_MIN_QUERIES:
                self.reason = "too few queries for automatic filtering"
                return
            self._build(rules, max_postings, max_pattern_chars, automatic, max_cache_bytes)
        except (sqlite3.Error, ValueError, TypeError, OverflowError, MemoryError, RecursionError) as exc:
            self.reason = str(exc)
            self.plans.clear()
            self.postings.clear()
            self.uncertain.clear()

    def _build(self, rules, max_postings, max_pattern_chars, automatic, max_cache_bytes):
        conn = self.connection
        with closing(conn.execute("PRAGMA table_info(logs)")) as cursor:
            columns = cursor.fetchall()
        if not any(name == "row_id" and typ.upper() == "INTEGER" and pk == 1 for _, name, typ, _, _, pk in columns):
            self.reason = "logs has no integer row_id primary key"
            return
        with closing(conn.execute("SELECT 1 FROM pragma_function_list WHERE lower(name)='like' AND builtin=0")) as cursor:
            if cursor.fetchone():
                self.reason = "LIKE has been overridden"
                return
        try:
            conn.execute("SELECT 1 FROM json_each('[]')").close()
        except sqlite3.Error:
            self.reason = "json_each is unavailable in this SQLite build"
            return
        with closing(conn.execute("SELECT count(*), min(row_id) FROM logs")) as cursor:
            self.total_rows, minimum = cursor.fetchone()
        if automatic and self.total_rows < AUTO_MIN_ROWS:
            self.reason = "too few events for automatic filtering"
            return
        if minimum is not None and minimum < 0:
            self.reason = "negative event IDs"
            return
        known = {name.translate(_ASCII_FOLD): name for _, name, *_ in columns}
        # PRAGMA table_info exposes declared types but not collations. Fail
        # closed for the whole table if an imported schema has RTRIM/custom
        # collation, while LIKE bounds remain available independently.
        text_columns = set()
        with closing(conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='logs'")) as cursor:
            schema = cursor.fetchone()
        if schema and schema[0] and census_collations_supported(schema[0]):
            text_columns = {
                name.translate(_ASCII_FOLD) for _, name, typ, *_ in columns
                if "INT" not in typ.upper() and any(part in typ.upper() for part in ("CHAR", "CLOB", "TEXT"))
            }
        like_limit = conn.getlimit(sqlite3.SQLITE_LIMIT_LIKE_PATTERN_LENGTH)
        patterns = defaultdict(set)
        queries = rule_queries(rules)
        normalized = (self.prepared or prepare_rules(queries)).normalized
        for query in queries:
            text = normalized.get(query) or normalize_rule_sql(query)
            plan = _plan_for(text)
            if plan is None or plan.sql in self.plans or plan.max_literal_bytes > like_limit:
                continue
            # Binding is cheap and compiling the WHERE clause is not, so a plan
            # with nothing to bound it on this table never reaches SQLite.
            bound = _bind_plan(plan, text_columns, known)
            if bound is None:
                continue
            runnable = self._runnable_plan(plan, text)
            if runnable is None:
                continue
            if runnable is not plan:
                bound = _bind_plan(runnable, text_columns, known)
                if bound is None:
                    continue
            plan = bound
            leaves = set(_leaves(plan.expression))
            self.plans[plan.sql] = plan
            self._partition_rows[plan.sql] = self._rows_within_bounds(plan.sql)
            for column, literal in leaves:
                patterns[column].add(literal)
        self.eligible_queries = len(self.plans)
        if max_postings is None:
            max_postings = _posting_budget(self.total_rows)
        if automatic and len(self.plans) < AUTO_MIN_QUERIES:
            self.reason = "too few eligible queries for automatic filtering"
            self.plans.clear()
            return
        # Complete columns survive another column exhausting a budget. Missing
        # postings mean unknown (the universe), never a partial candidate set.
        automata = {}
        column_counts: dict[str, int] = defaultdict(int)
        count = chars = 0
        for column, literals in sorted(patterns.items()):
            size = sum(map(len, literals))
            if chars + size > max_pattern_chars:
                self.skipped_columns[column] = "literal pattern budget exceeded"
                continue
            chars += size
            automaton = self.automaton_factory()
            for literal in literals:
                automaton.add_word(literal, literal)
                self.postings[column, literal] = self.bitmap_factory()
            automaton.make_automaton()
            automata[column] = automaton
            self.uncertain[column] = self.bitmap_factory()
        selected = tuple(automata)
        caches = {column: _ValueMatches(automaton, max_cache_bytes // len(selected))
                  for column, automaton in automata.items()}
        quoted = ', '.join('"' + known[column].replace('"', '""') + '"' for column in selected)
        if selected:
            with closing(conn.execute(f"SELECT row_id, {quoted} FROM logs")) as cursor:  # noqa: S608
                while rows := cursor.fetchmany(256):
                    if is_shutdown_requested():
                        raise ValueError("prefilter interrupted")
                    # Transpose one bounded batch in C, then scan each column.
                    # This avoids a zip and automaton lookup for every cell,
                    # particularly useful for sparse and single-column rules.
                    column_values = iter(zip(*rows, strict=True))
                    row_ids = next(column_values)
                    for column, values in zip(selected, column_values, strict=True):
                        cache = caches.get(column)
                        if cache is None:
                            continue
                        # Nearly every value repeats one seen before: read the
                        # cache inline and call into it only on a miss.
                        lookup, touch = cache.values.get, cache.values.move_to_end
                        uncertain = self.uncertain[column].add
                        postings = self.postings
                        added = 0
                        for row_id, value in zip(row_ids, values, strict=True):
                            if value is None:
                                continue
                            if not isinstance(value, str):
                                uncertain(row_id)
                                added += 1
                                continue
                            hit = lookup(value)
                            if hit is None:
                                matched = cache.matches(value)
                            else:
                                touch(value)
                                matched = hit[0]
                            for literal in matched:
                                postings[column, literal].add(row_id)
                            added += len(matched)
                        count += added
                        column_counts[column] += added
                        if count > max_postings:
                            self.skipped_columns[column] = "literal posting budget exceeded"
                            del automata[column]
                            del caches[column]
                            del self.uncertain[column]
                            for literal in patterns[column]:
                                del self.postings[column, literal]
                            count -= column_counts.pop(column)
                    if not automata:
                        break
        # Plans with no remaining necessary bound take the ordinary SQLite path.
        available = {key: self.bitmap_factory() for key in self.postings}
        self.plans = {sql: plan for sql, plan in self.plans.items()
                      if _evaluate(plan.expression, available) is not None}
        if not self.plans:
            self.reason = next(iter(self.skipped_columns.values()), "no eligible queries")
            self.postings.clear()
            self.uncertain.clear()

    def _runnable_plan(self, plan, text):
        """The plan SQLite will execute for this rule, or None if it cannot run.

        Broken rules must still take the ordinary repair/error path. A rule too
        deep to prepare is retried by the rule loop as ``rebalance_sql(text)``,
        so index that form: it is the SQL the loop will pass to rewrite().
        """
        try:
            self._explain(plan)
            return plan
        except sqlite3.Error as exc:
            if "expression tree is too large" not in str(exc).lower():
                return None
        rebalanced = _plan_for(rebalance_sql(text))
        if rebalanced is None or rebalanced.sql == plan.sql:
            return None
        try:
            self._explain(rebalanced)
        except sqlite3.Error:
            return None
        return rebalanced

    def _explain(self, plan):
        # Result columns cannot fail where the WHERE clause succeeds, and
        # compiling SELECT * costs one opcode per column of a wide table.
        # execute() has already prepared the statement, which is where every
        # error is raised. Reading the opcode listing would cost one GIL
        # round trip per row, and parallel workers convoy on that.
        self.connection.execute("EXPLAIN SELECT 1 FROM logs WHERE" + plan.sql[plan.where_start:]).close()  # noqa: S608 -- the rule's own WHERE clause

    def _rows_within_bounds(self, sql):
        """Rows the statement's Channel/EventID bounds select, per the census."""
        admitted = None if self.census is None else admitted_pairs(sql, self.census)
        return self.total_rows if admitted is None else sum(self.census[pair] for pair in admitted)

    def rewrite(self, sql):
        plan = self.plans.get(sql.strip().removesuffix(";").rstrip())
        if plan is None:
            return sql
        candidates = _evaluate(plan.expression, self.postings, self.uncertain)
        if candidates is None:
            self.unbounded_bypasses += 1
            return sql
        if not candidates:
            # _runnable_plan already compiled this WHERE clause on this
            # connection, and a plan that failed there was never indexed, so
            # compiling it again would find no new error. Most rules have no
            # candidates in most files: compiling each one again would be most
            # of the rule phase on many small files.
            self.accelerated += 1
            return NO_ROWS
        if len(candidates) >= BROAD_FRACTION * self._partition_rows.get(plan.sql, self.total_rows):
            self.broad_bypasses += 1
            return sql
        self.accelerated += 1
        head, body = plan.sql[:plan.where_start], plan.sql[plan.where_start:]
        # Row IDs are integers, so the JSON text needs no escaping. A literal keeps
        # rewrite() a plain statement; SQLite parses it once per execution.
        row_ids = orjson.dumps(list(candidates)).decode()
        return f"{head} logs.row_id IN (SELECT value FROM json_each('{row_ids}')) AND ({body})"  # noqa: S608 -- integers serialised by orjson

    def stats(self):
        return {
            "eligible_queries": self.eligible_queries, "indexed_queries": len(self.plans),
            "applied_queries": self.accelerated, "broad_bypasses": self.broad_bypasses,
            "unbounded_bypasses": self.unbounded_bypasses, "reason": self.reason,
            "skipped_columns": dict(self.skipped_columns),
            "postings": sum(map(len, self.postings.values())) + sum(map(len, self.uncertain.values())),
        }

    def close(self):
        """Release the index; it holds no database state."""
        self.plans.clear()
        self.postings.clear()
        self.uncertain.clear()

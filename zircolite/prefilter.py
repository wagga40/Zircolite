"""Conservative literal candidates for SQLite's built-in LIKE operator.

This is an accelerator, never an evaluator. Every returned candidate still
passes the original WHERE clause. None denotes the universe of rows, so an
unknown predicate cannot accidentally narrow a rule.
"""

import sqlite3
from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass
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
    iter_tokens,
    quote_sql_identifiers,
    rebalance_sql,
)

_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
AUTO_MIN_ROWS = 1000
AUTO_MIN_QUERIES = 32
# Share of the rows a rule's Channel/EventID bounds select past which the
# candidates narrow its scan too little to repay handing them over. Measured
# insensitive between 0.25 and 1.0 on HANCITOR; a third of a partition still won.
BROAD_FRACTION = 0.5
_UNSUPPORTED_WORDS = frozenset((
    "SELECT", "FROM", "WHERE", "JOIN", "UNION", "INTERSECT", "EXCEPT", "ORDER",
    "GROUP", "HAVING", "LIMIT", "OFFSET", "WINDOW", "CASE", "WHEN", "THEN",
    "ELSE", "END", "BETWEEN", "COLLATE", "OVER", "FILTER", "REGEXP", "GLOB", "MATCH",
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
            if kind == "punct" and value in (";", "?", ":", "@", "$", "."):
                return None
            # JSON operators can raise on rows the candidate set would skip.
            if (kind, value) == ("punct", "-") and body[i + 1:i + 2] == [("punct", ">")]:
                return None
            # Function calls may change error behavior when rows are skipped.
            if kind in ("word", "name") and body[i + 1:i + 2] == [("punct", "(")] and not (kind == "word" and value in ("IN", "NOT", "AND", "OR")):
                return None
        reader = _Reader(body)
        expression = reader.read_or()
        if reader.pos != len(body) or expression is None:
            return None
        return LiteralPlan(sql, ends[4], expression, longest)
    except (_Unsupported, RecursionError):
        return None


@lru_cache(maxsize=16384)
def _plan_for(sql):
    """Plans depend on the SQL text alone, so every file and worker shares them."""
    return _parse_literal_plan(sql.strip())


def _leaves(expression):
    if expression[0] == "literal":
        yield expression[1]
    else:
        for node in expression[1]:
            yield from _leaves(node)


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
    """Prepare SQL only; leave malformed rule values to the existing evaluator."""
    return tuple(query for rule in rules
                 if isinstance(rule.get("rule"), (list, tuple))
                 for query in rule["rule"] if isinstance(query, str))


@lru_cache(maxsize=8)
def prepare_rules(queries):
    """Share immutable SQL normalization across files; never cache database state."""
    return PreparedRules({sql: quote_sql_identifiers(sql) for sql in queries})


def clear_prepared_rules():
    prepare_rules.cache_clear()
    _plan_for.cache_clear()


class LiteralPrefilter:
    """One bounded candidate index for one ruleset execution over stable logs."""

    def __init__(self, connection, rules, *, automatic=False, automaton_factory=None, bitmap_factory=None,
                 max_postings=None, max_pattern_chars=1_000_000, prepared=None, census=None):
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
            self._build(rules, max_postings, max_pattern_chars, automatic)
        except (sqlite3.Error, ValueError, TypeError, OverflowError, MemoryError, RecursionError) as exc:
            self.reason = str(exc)
            self.plans.clear()
            self.postings.clear()
            self.uncertain.clear()

    def _build(self, rules, max_postings, max_pattern_chars, automatic):
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
        like_limit = 50000
        if hasattr(conn, "getlimit"):
            like_limit = conn.getlimit(getattr(sqlite3, "SQLITE_LIMIT_LIKE_PATTERN_LENGTH", 8))
        else:
            with closing(conn.execute("PRAGMA compile_options")) as cursor:
                for (option,) in cursor:
                    if option.startswith("MAX_LIKE_PATTERN_LENGTH="):
                        like_limit = int(option.split("=", 1)[1])
        patterns = defaultdict(set)
        queries = rule_queries(rules)
        normalized = (self.prepared or prepare_rules(queries)).normalized
        for query in queries:
            text = normalized.get(query) or quote_sql_identifiers(query)
            plan = _plan_for(text)
            if plan is None or plan.sql in self.plans or plan.max_literal_bytes > like_limit:
                continue
            leaves = set(_leaves(plan.expression))
            if any(column not in known for column, _ in leaves):
                continue
            plan = self._runnable_plan(plan, text)
            if plan is None:
                continue
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
                        automaton = automata.get(column)
                        if automaton is None:
                            continue
                        for row_id, value in zip(row_ids, values, strict=True):
                            if value is None:
                                continue
                            if not isinstance(value, str):
                                self.uncertain[column].add(row_id)
                                added = 1
                            else:
                                matched = {literal for _, literal in automaton.iter(value.translate(_ASCII_FOLD))}
                                for literal in matched:
                                    self.postings[column, literal].add(row_id)
                                added = len(matched)
                            count += added
                            column_counts[column] += added
                            if count > max_postings:
                                self.skipped_columns[column] = "literal posting budget exceeded"
                                del automata[column]
                                del self.uncertain[column]
                                for literal in patterns[column]:
                                    del self.postings[column, literal]
                                count -= column_counts.pop(column)
                                break
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
        with closing(self.connection.execute("EXPLAIN SELECT 1 FROM logs WHERE" + plan.sql[plan.where_start:])) as cursor:  # noqa: S608 -- the rule's own WHERE clause
            cursor.fetchall()

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
        head, body = plan.sql[:plan.where_start], plan.sql[plan.where_start:]
        if not candidates:
            # Still compiled, so a broken rule reports its error, but never scanned.
            self.accelerated += 1
            return f"{head} 0 AND ({body})"
        if len(candidates) >= BROAD_FRACTION * self._partition_rows.get(plan.sql, self.total_rows):
            self.broad_bypasses += 1
            return sql
        self.accelerated += 1
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

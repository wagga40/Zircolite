"""Quote-aware reading and repair of rule SQL.

Rule SQL arrives from ``pysigma-backend-sqlite`` and has to be inspected before
it can be trusted: which columns does it name, which eventIDs can it actually
match, and is its OR chain too deep for SQLite to parse? All three questions
need the same thing -- a scan that knows where string literals and quoted
identifiers begin and end.

A plain regex does not. It reads ``'%user=bob%'`` inside a CommandLine pattern
as a column named ``user``, and it cannot see ```event.code``` at all, because
the backend backtick-quotes every field name that is not ``^[a-zA-Z0-9_]*$`` --
which is every ECS and Winlogbeat name. Both mistakes are silent, and both end
in a rule that matches nothing while reporting no error.

Since they all want the same scan, they share one. ``scan_query`` lexes a
statement once, answers every question from that single token list and memoises
the answers; the public readers below are folds over it. Lexing is the dominant
cost of reading a ruleset -- roughly 100 ms per megabyte of SQL, against a
merged ruleset that carries several -- and per-file and parallel modes ask the
same questions of the same statements once per input file.
"""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import lru_cache

# Opening delimiter -> its closer. Only ``'`` introduces a string literal; the
# rest quote identifiers, which is why they are told apart below.
_CLOSERS = {"'": "'", '"': '"', "`": "`", "[": "]"}

# Below this, the chain cannot be what breached the depth limit, and wrapping
# it in parentheses would only make the SQL harder to read in --debug output.
_MIN_OR_TERMS = 8

_TAIL_KEYWORDS = ("GROUP", "ORDER", "LIMIT", "HAVING", "WINDOW")
_COMPOUND_KEYWORDS = ("UNION", "INTERSECT", "EXCEPT")

# Words that put a column name on their left rather than being one themselves.
_COMPARISON_WORDS = frozenset({"LIKE", "IN", "BETWEEN", "IS", "GLOB", "MATCH", "REGEXP"})

# Single characters that begin a comparison operator. Two-character operators
# such as ``!=`` and ``<>`` arrive as two punctuation tokens; adding the same
# name to a set twice is harmless, so they need no special case.
_COMPARISON_PUNCT = frozenset("=<>!")

SQL_RESERVED_WORDS = frozenset({
    "select", "from", "where", "and", "or", "not", "in", "is", "null",
    "like", "between", "exists", "case", "when", "then", "else", "end",
    "as", "on", "join", "inner", "outer", "left", "right", "full",
    "order", "by", "group", "having", "limit", "offset", "asc", "desc",
    "distinct", "all", "union", "intersect", "except", "escape",
    "true", "false",
})


class _Unsupported(Exception):
    """The statement has a shape this module does not model."""


def _closing_quote(sql: str, i: int) -> int | None:
    """Index just past the quoted run starting at ``i``, or None if none starts there."""
    char = sql[i]
    if char not in _CLOSERS:
        return None
    closer = _CLOSERS[char]
    j = i + 1
    while j < len(sql):
        if sql[j] == closer:
            # '' and "" and `` are escaped quotes; [] has no doubling rule
            if closer != "]" and sql.startswith(closer * 2, j):
                j += 2
                continue
            return j + 1
        j += 1
    raise _Unsupported("unterminated quoted run")


def _quoted_span(sql: str, i: int) -> int | None:
    """``_closing_quote``, but refusing comments.

    The rewriter appends parentheses; one landing after a ``--`` would be
    swallowed by it, so a statement carrying comments is left alone entirely.
    """
    if sql[i] not in _CLOSERS and (sql.startswith("--", i) or sql.startswith("/*", i)):
        raise _Unsupported("comment")
    return _closing_quote(sql, i)


def _is_word(sql: str, i: int, word: str) -> bool:
    """True when ``word`` sits at ``i`` as a whole token, case-insensitively."""
    if sql[i : i + len(word)].upper() != word:
        return False
    before = sql[i - 1] if i else " "
    after = sql[i + len(word)] if i + len(word) < len(sql) else " "
    return not (before.isalnum() or before == "_") and not (
        after.isalnum() or after == "_"
    )


def _unquote(text: str) -> str:
    """Strip an identifier's quotes, undoubling any escaped closer inside."""
    closer = _CLOSERS[text[0]]
    inner = text[1:-1]
    return inner if closer == "]" else inner.replace(closer * 2, closer)


def iter_tokens(sql: str) -> Iterator[tuple[str, int, int]]:
    """Yield ``(kind, start, end)`` across ``sql``.

    ``kind`` is ``literal`` for ``'...'``, ``identifier`` for a quoted name,
    ``word`` for a bare name or keyword, ``number`` for a numeric literal,
    ``comment`` for either comment form, and ``punct`` for a single character of
    anything else. Quoted runs are never split, so nothing inside a string
    literal can be mistaken for a name.
    """
    i, n = 0, len(sql)
    while i < n:
        char = sql[i]
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            end = n if end < 0 else end
            yield ("comment", i, end)
            i = end
            continue
        if sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            end = n if end < 0 else end + 2
            yield ("comment", i, end)
            i = end
            continue
        quoted_end = _closing_quote(sql, i)
        if quoted_end is not None:
            yield ("literal" if char == "'" else "identifier", i, quoted_end)
            i = quoted_end
            continue
        if char.isalpha() or char == "_":
            j = i + 1
            while j < n and (sql[j].isalnum() or sql[j] == "_"):
                j += 1
            yield ("word", i, j)
            i = j
            continue
        if char.isdigit():
            j = i + 1
            while j < n and (sql[j].isdigit() or sql[j] == "."):
                j += 1
            yield ("number", i, j)
            i = j
            continue
        yield ("punct", i, i + 1)
        i += 1


@lru_cache(maxsize=1024)
def quote_sql_identifiers(sql: str) -> str:
    """Prevent SQLite from interpreting missing double-quoted names as strings.

    Also works on Python 3.10/3.11, which cannot disable DQS via setconfig.
    String literals and comments are preserved byte for byte.
    """
    try:
        return _apply_edits(sql, _identifier_edits(sql, iter_tokens(sql)))
    except _Unsupported:
        return sql


def _identifier_edits(sql: str, tokens: Iterable[tuple[str, int, int]]) -> list[tuple[int, int, int, str]]:
    return [(start, 2, end, "`" + _unquote(sql[start:end]).replace("`", "``") + "`")
            for kind, start, end in tokens if kind == "identifier" and sql[start] == '"']


# A NOT opens an operand only where an operand can start. Anywhere else it is
# part of NOT LIKE, NOT IN, IS NOT NULL and the like, which compare rather than
# negate a condition.
_PREFIX_NOT_AFTER = frozenset({"WHERE", "AND", "OR", "NOT"})
_STOPS_OPERAND = frozenset({"AND", "OR", *_TAIL_KEYWORDS})


def _negation_edits(sql: str, tokens: list[tuple[str, int, int]]) -> list[tuple[int, int, int, str]]:
    """Edits wrapping every prefix NOT's operand in ``COALESCE((...), 0)``.

    NOT binds tighter than AND and OR and looser than every comparison, so its
    operand runs to the next AND/OR, closing parenthesis or tail clause at its
    own depth. A BETWEEN or CASE there carries an AND of its own, which would
    end the operand too early; that NOT is left as written.
    """
    edits: list[tuple[int, int, int, str]] = []
    for i, (kind, start, end) in enumerate(tokens):
        if kind != "word" or sql[start:end].upper() != "NOT" or i + 1 == len(tokens):
            continue
        if i:
            before_kind, before_start, before_end = tokens[i - 1]
            before = sql[before_start:before_end]
            if not ((before_kind == "word" and before.upper() in _PREFIX_NOT_AFTER)
                    or (before_kind == "punct" and before == "(")):
                continue
        after_kind, after_start, after_end = tokens[i + 1]
        if after_kind == "word" and sql[after_start:after_end].upper() == "COALESCE":
            continue
        depth, j, last = 0, i + 1, i
        while j < len(tokens):
            kind_j, start_j, end_j = tokens[j]
            text = sql[start_j:end_j]
            if kind_j == "punct" and text == "(":
                depth += 1
            elif kind_j == "punct" and text == ")":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and kind_j == "punct" and text == ";":
                break
            elif depth == 0 and kind_j == "word":
                word = text.upper()
                if word in _STOPS_OPERAND:
                    break
                if word in ("BETWEEN", "CASE"):
                    last = i
                    break
            last = j
            j += 1
        if last == i or depth:
            continue
        first_start = tokens[i + 1][1]
        last_end = tokens[last][2]
        group = sql[first_start] == "(" and _closes_at(sql, tokens, i + 1) == last
        edits.append((first_start, 1, first_start, "COALESCE(" if group else "COALESCE(("))
        edits.append((last_end, 0, last_end, ", 0)" if group else "), 0)"))
    return edits


def _closes_at(sql: str, tokens: list[tuple[str, int, int]], opening: int) -> int:
    """Index of the token closing the parenthesis at ``opening``."""
    depth = 0
    for j in range(opening, len(tokens)):
        if tokens[j][0] == "punct":
            char = sql[tokens[j][1]]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return j
    return -1


def _apply_edits(sql: str, edits: list[tuple[int, int, int, str]]) -> str:
    """Apply ``(start, order, end, text)`` edits: ``text`` replaces ``sql[start:end]``.

    Insertions (start == end) sharing a position go in ``order``: a closing
    wrapper before an opening one, both before a replaced token starting there.
    """
    if not edits:
        return sql
    parts: list[str] = []
    previous = 0
    for start, _, end, text in sorted(edits):
        parts.extend((sql[previous:start], text))
        previous = end
    parts.append(sql[previous:])
    return "".join(parts)


def _significant(sql: str, tokens: Iterable[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    return [(kind, start, end) for kind, start, end in tokens
            if kind != "comment" and not (kind == "punct" and sql[start:end].isspace())]


def null_safe_negation(sql: str) -> str:
    """Make every negated condition read a missing field as a non-match.

    Sigma reads a condition on a field the event does not carry as false, so
    ``selection and not filter`` holds when the filter names such a field.
    SQLite evaluates the comparison to NULL instead, and ``NOT NULL`` is NULL,
    so the row was dropped: Sysmon network events have no CommandLine, and a
    network rule whose filters mention one matched nothing. Each negated
    operand becomes ``COALESCE((operand), 0)``, turning that NULL back into the
    false Sigma means. Nested negations are rewritten too, so what reaches a
    COALESCE is AND/OR over comparisons, and reading its NULL as false is
    exactly Sigma's answer.
    """
    try:
        tokens = _significant(sql, iter_tokens(sql))
    except _Unsupported:
        return sql
    return _apply_edits(sql, _negation_edits(sql, tokens))


@lru_cache(maxsize=1024)
def normalize_rule_sql(sql: str) -> str:
    """The text a rule statement is run, planned and repaired as.

    Double-quoted names become backtick-quoted (see ``quote_sql_identifiers``)
    and negation becomes null-safe (see ``null_safe_negation``), from one lex.
    """
    try:
        tokens = _significant(sql, iter_tokens(sql))
    except _Unsupported:
        return sql
    return _apply_edits(sql, _negation_edits(sql, tokens) + _identifier_edits(sql, tokens))


def _typed_tokens(sql: str) -> list[tuple[str, str]]:
    """``iter_tokens`` as ``(kind, text)``, ready for the readers below.

    Identifiers arrive unquoted, and whitespace and comments are dropped: both
    readers work on adjacency, so a space between ``NOT`` and ``(`` must not
    look like a token.
    """
    out: list[tuple[str, str]] = []
    for kind, start, end in iter_tokens(sql):
        if kind == "comment":
            continue
        text = sql[start:end]
        if kind == "punct" and text.isspace():
            continue
        out.append(("name", _unquote(text)) if kind == "identifier" else (kind, text))
    return out


def _peek(tokens: list[tuple[str, str]], pos: int) -> tuple[str, str]:
    return tokens[pos] if pos < len(tokens) else ("end", "")


def _peek_word(tokens: list[tuple[str, str]], pos: int) -> str:
    kind, text = _peek(tokens, pos)
    return text.upper() if kind == "word" else ""


def _regex_patterns(tokens: list[tuple[str, str]]) -> tuple[str, ...]:
    """The patterns ``tokens`` hands to REGEXP, stripped of their SQL quoting."""
    patterns: list[str] = []
    for i, (kind, text) in enumerate(tokens):
        if kind == "word" and text.upper() == "REGEXP":
            kind_, text_ = _peek(tokens, i + 1)
            if kind_ == "literal":
                patterns.append(text_[1:-1].replace("''", "'"))
    return tuple(patterns)


def regex_literals(sql: str) -> list[str]:
    """The patterns ``sql`` hands to REGEXP, stripped of their SQL quoting.

    A pattern Python cannot compile has to be reported before the rule runs.
    Left to the UDF, it raises once per row and is swallowed once per row, and
    the rule ends up indistinguishable from one that simply matched nothing.
    """
    return list(scan_query(sql).regex_patterns)


def _column_names(tokens: list[tuple[str, str]]) -> frozenset[str]:
    """Column names ``tokens`` compares against, minus SQL keywords."""
    names: set[str] = set()
    previous: str | None = None
    expect_operand = False
    for kind, text in tokens:
        if kind == "name":
            if expect_operand:
                names.add(text)
                expect_operand = False
            previous = text
        elif kind == "word":
            upper = text.upper()
            if upper in _COMPARISON_WORDS:
                if previous is not None:
                    names.add(previous)
                expect_operand = True
            elif upper == "NOT":
                # Keeps ``x NOT LIKE y`` and ``x IS NOT NULL`` pointing at x
                continue
            elif text.lower() in SQL_RESERVED_WORDS:
                previous = None
                expect_operand = False
            else:
                if expect_operand:
                    names.add(text)
                    expect_operand = False
                previous = text
        elif kind == "punct" and text in _COMPARISON_PUNCT:
            if previous is not None:
                names.add(previous)
            expect_operand = True
        else:
            expect_operand = False
    return frozenset(names)


def column_refs(sql: str) -> set[str]:
    """Column names ``sql`` compares against, minus SQL keywords.

    Quoted names count -- ```event.code``` is a column, and the backend quotes
    every field name carrying a dot, ``@``, bracket or space. Text inside a
    string literal never does: ``CommandLine LIKE '%user=bob%'`` names one
    column, not two.

    Both sides of a comparison count. Sigma's ``|fieldref`` compares two fields,
    and a right-hand name the caller never hears about is one it cannot widen
    the table for -- leaving the query to keep failing on ``no such column``.
    Only a bare identifier qualifies: literals and numbers are values.
    """
    return set(scan_query(sql).columns)


# ---------------------------------------------------------------------------
# Which values of a field can a rule actually match?
#
# ``None`` means unbounded: any value might match, so the caller must not narrow
# anything. That is the answer whenever the SQL does not constrain the field,
# constrains it under a NOT (where the listed values are the ones the rule
# *excludes*), or has a shape this cannot read. Every uncertainty fails open,
# because a wrong bound drops events at ingest and the rule then finds nothing
# while looking perfectly healthy.
#
# The algebra is the same whichever field is being read: AND intersects (an
# unconstrained side narrows nothing), OR unions (one free branch frees the
# whole disjunction), and NOT surrenders.
# ---------------------------------------------------------------------------


def _as_int(kind: str, text: str) -> int | None:
    """The integer a value token denotes, or None if it denotes none."""
    if kind == "number":
        raw = text
    elif kind == "literal":
        raw = text[1:-1]
    else:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _as_text(kind: str, text: str) -> str | None:
    """The string a value token denotes, or None if it denotes none."""
    if kind == "literal":
        return text[1:-1].replace("''", "'")
    return text if kind == "number" else None


class _FieldReader:
    """Reads the values one field is pinned to across a WHERE clause."""

    def __init__(self, field: str, coerce):
        self.field = field.lower()
        self.coerce = coerce

    def read(self, tokens: list[tuple[str, str]], start: int) -> set | None:
        value, end = self._or(tokens, start)
        return value if end == len(tokens) else None

    def _atom_values(self, atom: list[tuple[str, str]]) -> set | None:
        # Only complete, direct comparisons prove a bound. Searching inside
        # arbitrary expressions mistook EventID=1+1 for EventID=1, for example.
        kind, name = _peek(atom, 0)
        if kind not in ("word", "name") or name.lower() != self.field:
            return None
        if len(atom) == 3 and atom[1] == ("punct", "="):
            value = self.coerce(*atom[2])
            return None if value is None else {value}
        if (len(atom) >= 5 and _peek_word(atom, 1) == "IN"
                and atom[2] == ("punct", "(") and atom[-1] == ("punct", ")")):
            values = set()
            for i, token in enumerate(atom[3:-1]):
                if i % 2:
                    if token != ("punct", ","):
                        return None
                else:
                    value = self.coerce(*token)
                    if value is None:
                        return None
                    values.add(value)
            if len(atom[3:-1]) % 2:
                return values or None
        return None

    def _atom(self, tokens: list[tuple[str, str]], pos: int) -> tuple[set | None, int]:
        """Consume one comparison, up to the next connective at this depth.

        ``x BETWEEN a AND b`` is cut at its AND, leaving two atoms that each pin
        down nothing. The answer is then None, which is the safe one.
        """
        start, depth = pos, 0
        while pos < len(tokens):
            kind, text = tokens[pos]
            if kind == "punct":
                if text == "(":
                    depth += 1
                elif text == ")":
                    if depth == 0:
                        break
                    depth -= 1
            elif kind == "word" and depth == 0 and text.upper() in ("AND", "OR"):
                break
            pos += 1
        return self._atom_values(tokens[start:pos]), pos

    def _primary(
        self, tokens: list[tuple[str, str]], pos: int
    ) -> tuple[set | None, int]:
        if _peek(tokens, pos) == ("punct", "("):
            value, pos = self._or(tokens, pos + 1)
            if _peek(tokens, pos) != ("punct", ")"):
                raise _Unsupported("unbalanced parentheses")
            return value, pos + 1
        return self._atom(tokens, pos)

    def _not(self, tokens: list[tuple[str, str]], pos: int) -> tuple[set | None, int]:
        if _peek_word(tokens, pos) == "NOT":
            # The values under a NOT are the ones the rule refuses. Reading them
            # as the ones it wants inverts the rule; see EventFilter in rules.py.
            _, pos = self._not(tokens, pos + 1)
            return None, pos
        return self._primary(tokens, pos)

    def _and(self, tokens: list[tuple[str, str]], pos: int) -> tuple[set | None, int]:
        value, pos = self._not(tokens, pos)
        while _peek_word(tokens, pos) == "AND":
            right, pos = self._not(tokens, pos + 1)
            if value is None:
                value = right
            elif right is not None:
                value &= right
        return value, pos

    def _or(self, tokens: list[tuple[str, str]], pos: int) -> tuple[set | None, int]:
        value, pos = self._and(tokens, pos)
        while _peek_word(tokens, pos) == "OR":
            right, pos = self._and(tokens, pos + 1)
            value = None if value is None or right is None else value | right
        return value, pos


@dataclass(frozen=True, slots=True)
class QueryScan:
    """Everything one statement can be asked about, read in a single pass.

    ``channels`` and ``eventids`` follow the convention above: ``None`` is
    unbounded, and an empty frozenset is the rarer "provably matches nothing".
    """

    channels: frozenset[str] | None
    eventids: frozenset[int] | None
    columns: frozenset[str]
    regex_patterns: tuple[str, ...]


_UNSCANNABLE = QueryScan(None, None, frozenset(), ())

# Keyed by the statement text, which is what every fact here is a pure function
# of -- no schema, no database, no config, no file. Nothing can invalidate an
# entry, so per-file and parallel modes reuse one warm cache for the whole run
# instead of re-lexing the ruleset once per input file. Values are immutable, so
# two threads racing on the same statement can only write equal answers; that is
# why this is a plain dict and not a lock-taking ``lru_cache``.
_SCANS: dict[str, QueryScan] = {}


def scan_query(sql: str) -> QueryScan:
    """Read ``sql`` once, answering every question this module supports."""
    cached = _SCANS.get(sql)
    if cached is not None:
        return cached

    try:
        tokens = _typed_tokens(sql)
    except _Unsupported:
        # Unscannable SQL cannot be repaired here, and will fail loudly when run.
        _SCANS[sql] = _UNSCANNABLE
        return _UNSCANNABLE

    where = next(
        (
            i + 1
            for i, (kind, text) in enumerate(tokens)
            if kind == "word" and text.upper() == "WHERE"
        ),
        None,
    )

    def bounds(reader: _FieldReader) -> frozenset | None:
        # One try per reader on purpose: they recurse identically, so a shared
        # one would let the channel reader's blow-up decide the eventID answer.
        if where is None:
            return None
        words = [text.upper() for kind, text in tokens if kind == "word"]
        if any(word in words for word in
                (*_COMPOUND_KEYWORDS, "WITH", "JOIN", "CASE", "BETWEEN")):
            return None
        # GROUP/ORDER/etc. do not constrain the input. Stop at the first tail
        # clause; require the boolean reader to consume the entire predicate.
        end = next((i for i in range(where, len(tokens))
                    if tokens[i][0] == "word" and tokens[i][1].upper() in _TAIL_KEYWORDS), len(tokens))
        if words.count("SELECT") == 2:
            # Recognize only the backend's single-input aggregation wrapper:
            # SELECT ... FROM (SELECT ... FROM logs WHERE ...) AS name GROUP ...
            # Arbitrary subqueries can negate or otherwise change the meaning
            # of their inner predicate and must remain unbounded.
            froms = [i for i in range(len(tokens)) if _peek_word(tokens, i) == "FROM"]
            if (len(froms) != 2 or words.count("WHERE") != 1
                    or _peek(tokens, froms[0] + 1) != ("punct", "(")
                    or _peek_word(tokens, froms[0] + 2) != "SELECT"
                    or _peek(tokens, froms[1] + 1)[1].lower() != "logs"
                    or froms[1] + 3 != where):
                return None
            depth = 0
            closing = None
            for i in range(where, end):
                if tokens[i] == ("punct", "("):
                    depth += 1
                elif tokens[i] == ("punct", ")"):
                    if depth == 0:
                        closing = i
                        break
                    depth -= 1
            if closing is None:
                return None
            alias = tokens[closing + 1:end]
            if alias and alias[-1] == ("punct", ";"):
                alias = alias[:-1]
            if alias and _peek_word(alias, 0) == "AS":
                alias = alias[1:]
            if len(alias) > 1 or (alias and alias[0][0] not in ("word", "name")):
                return None
            end = closing
        elif words.count("SELECT") != 1:
            return None
        predicate = tokens[where:end]
        if predicate and predicate[-1] == ("punct", ";"):
            predicate = predicate[:-1]
        try:
            value = reader.read(predicate, 0)
        except (_Unsupported, RecursionError):
            return None
        return None if value is None else frozenset(value)

    scan = QueryScan(
        channels=bounds(_FieldReader("channel", _as_text)),
        eventids=bounds(_FieldReader("eventid", _as_int)),
        columns=_column_names(tokens),
        regex_patterns=_regex_patterns(tokens),
    )
    _SCANS[sql] = scan
    return scan


def clear_scan_cache() -> None:
    """Drop every memoised scan. For tests and long-lived library callers."""
    _SCANS.clear()


def _constraints(queries: list[str], field: str) -> set | None:
    """Union of one field's bounds across a rule's statements, or None.

    A rule matches when any one of its statements does, so a single unbounded
    statement leaves the whole rule unbounded.
    """
    total: set = set()
    for query in queries:
        if not isinstance(query, str):
            return None
        value = getattr(scan_query(query), field)
        if value is None:
            return None
        total |= value
    return total or None


def admitted_pairs(sql: str, pairs: Iterable[tuple]) -> list[tuple] | None:
    """The ``(channel, eventid)`` pairs ``sql``'s bounds admit, or None if unbounded.

    Channels in ``pairs`` must already be lower-cased: the Channel column is
    NOCASE, so the bounds are folded the same way before comparing.
    """
    scan = scan_query(sql)
    if scan.channels is None and scan.eventids is None:
        return None
    channels = None if scan.channels is None else {channel.lower() for channel in scan.channels}
    eventids = scan.eventids
    return [pair for pair in pairs
            if (channels is None or pair[0] in channels) and (eventids is None or pair[1] in eventids)]


def eventid_constraints(queries: list[str]) -> set[int] | None:
    """The eventIDs a rule's SQL can match, or None when it cannot be bounded."""
    return _constraints(queries, "eventids")


def channel_constraints(queries: list[str]) -> set[str] | None:
    """The channels a rule's SQL can match, or None when it cannot be bounded."""
    return _constraints(queries, "channels")


def _balance(parts: list) -> str:
    if len(parts) == 1:
        return parts[0]
    mid = len(parts) // 2
    return f"({_balance(parts[:mid])} OR {_balance(parts[mid:])})"


def _rewrite(sql: str, lo: int, hi: int) -> str:
    """Rewrite ``sql[lo:hi]``, recursing into parenthesised groups.

    Only OR is re-associated. AND is reproduced exactly as written: the AND in
    ``x BETWEEN a AND b`` is syntax rather than a boolean operator, and
    re-associating it changes the result without raising an error.
    """
    out: list = []
    operands: list = []
    i = lo
    while i < hi:
        after_quote = _quoted_span(sql, i)
        if after_quote is not None:
            out.append(sql[i:after_quote])
            i = after_quote
            continue
        char = sql[i]
        if char == "(":
            depth, j = 1, i + 1
            while j < hi and depth:
                span = _quoted_span(sql, j)
                if span is not None:
                    j = span
                    continue
                if sql[j] == "(":
                    depth += 1
                elif sql[j] == ")":
                    depth -= 1
                j += 1
            if depth:
                raise _Unsupported("unbalanced parentheses")
            out.append("(" + _rewrite(sql, i + 1, j - 1) + ")")
            i = j
            continue
        if char == ")":
            raise _Unsupported("unbalanced parentheses")
        # A parenthesised group holding a SELECT is a subquery, not a boolean
        # expression. Re-associating the ORs inside ``x IN (SELECT ... OR ...)``
        # turns the subquery into a truth value: it still parses, and the rule
        # then matches the wrong rows.
        if _is_word(sql, i, "SELECT"):
            raise _Unsupported("subquery")
        # CASE ... END is opaque: an OR inside it is bounded by WHEN/THEN/ELSE,
        # so splitting there would cut the expression in the wrong place.
        if _is_word(sql, i, "CASE"):
            depth, j = 1, i + 4
            while j < hi and depth:
                span = _quoted_span(sql, j)
                if span is not None:
                    j = span
                    continue
                if _is_word(sql, j, "CASE"):
                    depth += 1
                elif _is_word(sql, j, "END"):
                    depth -= 1
                j += 1
            if depth:
                raise _Unsupported("unterminated CASE")
            out.append(sql[i:j])
            i = j
            continue
        if _is_word(sql, i, "OR"):
            operands.append("".join(out))
            out = []
            i += 2
            continue
        out.append(char)
        i += 1
    operands.append("".join(out))
    if len(operands) < _MIN_OR_TERMS:
        # Operands carry the whitespace that surrounded each OR, so joining on
        # the bare keyword reproduces the input byte for byte.
        return "OR".join(operands)
    if any(not part.strip() for part in operands):
        # A tail keyword used as a bare identifier can cut the span short.
        raise _Unsupported("empty OR operand")
    return _balance([part.strip() for part in operands])


# Rebalancing a 350 KB rule takes ~100 ms, and per-file and parallel modes run the
# same ruleset once per input file -- through both the rule loop and the literal
# prefilter. Only a handful of rules ever need it.
@lru_cache(maxsize=32)
def rebalance_sql(sql: str) -> str:
    """Return ``sql`` with deep OR chains re-associated into a balanced tree.

    ``pysigma-backend-sqlite`` emits value lists as a left-deep chain
    (``a OR b OR c OR ...``), whose parse-tree depth equals the number of terms.
    SQLite refuses anything past ``SQLITE_MAX_EXPR_DEPTH`` (1000 by default), so
    a rule listing a few thousand hashes never runs at all. The limit cannot be
    raised from Python: ``sqlite3_limit`` clamps to the compile-time bound, and
    ``Connection.setlimit`` only exists on Python 3.11+. Re-emitting the same
    terms as a balanced binary tree brings the depth down to O(log n) without
    touching the meaning of the expression.

    Returns ``sql`` unchanged whenever the statement's shape is not one this can
    rewrite safely. Emitting subtly wrong SQL would be far worse than leaving a
    rule reported as broken, so every uncertainty bails out.
    """
    try:
        i, depth, where, end = 0, 0, -1, len(sql)
        while i < len(sql):
            after_quote = _quoted_span(sql, i)
            if after_quote is not None:
                i = after_quote
                continue
            char = sql[i]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth < 0:
                    return sql
            elif depth == 0:
                if any(_is_word(sql, i, kw) for kw in _COMPOUND_KEYWORDS):
                    return sql
                if where < 0 and _is_word(sql, i, "WHERE"):
                    where = i + 5
                elif (
                    where >= 0
                    and end == len(sql)
                    and (
                        char == ";"
                        or any(_is_word(sql, i, kw) for kw in _TAIL_KEYWORDS)
                    )
                ):
                    end = i
            i += 1
        if where < 0 or depth != 0:
            return sql
        return sql[:where] + _rewrite(sql, where, end) + sql[end:]
    except (_Unsupported, RecursionError):
        return sql

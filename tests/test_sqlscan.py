"""Tests for the quote-aware SQL scanner and the OR-chain rebalancer."""

import sqlite3
from contextlib import closing

import pytest

from zircolite.sqlscan import (
    channel_constraints,
    column_refs,
    eventid_constraints,
    rebalance_sql,
)


def _depth(sql: str) -> int:
    """Maximum parenthesis nesting depth of a SQL string."""
    depth = best = 0
    for char in sql:
        if char == "(":
            depth += 1
            best = max(best, depth)
        elif char == ")":
            depth -= 1
    return best


def _chain(terms: int, column: str = "CommandLine") -> str:
    body = " OR ".join(f"{column} LIKE '%v{i}%' ESCAPE '\\'" for i in range(terms))
    return f"SELECT * FROM logs WHERE Channel='Security' AND (EventID=4688 AND ({body}))"


class TestRebalanceFixesDepthLimit:
    """The rebalancer must make over-deep statements parseable."""

    def test_oversized_chain_compiles_after_rebalance(self):
        with closing(sqlite3.connect(":memory:")) as conn:
            conn.execute(
                "CREATE TABLE logs (Channel TEXT, EventID TEXT, CommandLine TEXT)"
            )
            query = _chain(2000)

            with pytest.raises(
                sqlite3.OperationalError, match="Expression tree is too large"
            ):
                conn.execute(query)

            conn.execute(f"EXPLAIN {rebalance_sql(query)}")

    def test_depth_becomes_logarithmic(self):
        rewritten = rebalance_sql(_chain(1024))
        # A left-deep chain nests once per term; a balanced tree nests log2(n).
        assert _depth(rewritten) < 32

    def test_nested_chain_is_reached(self):
        """The chain sits under two ANDs, so a top-level split alone finds nothing."""
        assert rebalance_sql(_chain(64)) != _chain(64)

    def test_rebalance_is_idempotent(self):
        once = rebalance_sql(_chain(512))
        assert rebalance_sql(once) == once


class TestRebalancePreservesMeaning:
    """Rewritten SQL must return exactly what the original returned."""

    @pytest.fixture
    def conn(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE logs (a, b, c)")
        conn.executemany(
            "INSERT INTO logs VALUES (?, ?, ?)", [(3, 9, 1), (7, 2, 1), (3, 2, 1)]
        )
        yield conn
        conn.close()

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT * FROM logs WHERE a=3 OR b=2 OR c=1",
            "SELECT * FROM logs WHERE (a=3 AND b=9) OR (a=7 AND (b=2 OR c=1))",
            "SELECT * FROM logs WHERE NOT (a=3 OR b=2) OR c=1",
            "SELECT * FROM logs WHERE a IN (SELECT b FROM logs WHERE c=1 OR c=2) OR b=9",
            "SELECT c FROM logs WHERE a=3 OR b=2 GROUP BY c HAVING COUNT(*) > 0",
            "SELECT * FROM logs WHERE a=3 OR b=2 ORDER BY a LIMIT 2",
        ],
    )
    def test_results_are_identical(self, conn, query):
        assert conn.execute(query).fetchall() == conn.execute(
            rebalance_sql(query)
        ).fetchall()

    @pytest.mark.parametrize(
        "query",
        [
            # The AND in BETWEEN is syntax, not a boolean operator: re-associating
            # it compiles cleanly and silently returns the wrong rows.
            "SELECT * FROM logs WHERE a BETWEEN 1 AND 5 AND b=2",
            "SELECT * FROM logs WHERE a NOT BETWEEN 1 AND 5 AND b=9",
        ],
    )
    def test_between_is_never_reassociated(self, conn, query):
        assert conn.execute(query).fetchall() == conn.execute(
            rebalance_sql(query)
        ).fetchall()

    def test_case_expression_is_not_split(self, conn):
        query = "SELECT * FROM logs WHERE CASE WHEN a=3 THEN b=9 ELSE c=1 END OR a=7"
        assert conn.execute(query).fetchall() == conn.execute(
            rebalance_sql(query)
        ).fetchall()


class TestRebalanceBailsOut:
    """Unmodelled shapes must come back untouched rather than half-rewritten."""

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT * FROM logs",  # no WHERE
            "SELECT * FROM logs WHERE a=1 -- OR b=2\n OR c=3",  # line comment
            "SELECT * FROM logs WHERE a=1 OR b=2 UNION SELECT * FROM logs WHERE c=3",
            "SELECT * FROM logs WHERE a=1 OR b=2 EXCEPT SELECT * FROM logs WHERE c=3",
            "SELECT * FROM logs WHERE (a=1 OR b=2",  # unbalanced parenthesis
            "SELECT * FROM logs WHERE a='unterminated OR b=2",
        ],
    )
    def test_returns_input_unchanged(self, query):
        assert rebalance_sql(query) == query

    def test_short_chain_is_left_alone(self):
        query = "SELECT * FROM logs WHERE a=1 OR b=2 OR c=3"
        assert rebalance_sql(query) == query


class TestRebalanceLexing:
    """`OR` inside a quoted run is data, not an operator."""

    def test_or_inside_string_literal_is_not_split(self):
        query = "SELECT * FROM logs WHERE a='x OR y' OR b='p OR q' OR c=1"
        assert "'x OR y'" in rebalance_sql(query)
        assert "'p OR q'" in rebalance_sql(query)

    @pytest.mark.parametrize("quoted", ['"we OR ird"', "`we OR ird`", "[we OR ird]"])
    def test_or_inside_quoted_identifier_is_not_split(self, quoted):
        query = f"SELECT * FROM logs WHERE {quoted}=1 OR a=2"
        assert quoted in rebalance_sql(query)

    def test_doubled_quote_inside_literal(self):
        query = "SELECT * FROM logs WHERE a='it''s OR fine' OR b=1"
        assert "'it''s OR fine'" in rebalance_sql(query)

    def test_tail_keyword_inside_literal_is_not_the_tail(self):
        query = "SELECT * FROM logs WHERE a='x ORDER BY y' OR b=1"
        assert "'x ORDER BY y'" in rebalance_sql(query)


class TestRebalanceRefusesNonBooleanParens:
    """A parenthesised group holding a SELECT is a subquery, not an expression."""

    def test_or_chain_inside_a_subquery_is_left_alone(self):
        """Re-associating it turns the subquery into a truth value.

        The result still prepares cleanly, which is what makes it dangerous:
        ``x IN (SELECT ...)`` silently becomes ``x IN (0 or 1)``.
        """
        body = " OR ".join(f"a={i}" for i in range(12))
        query = f"SELECT * FROM logs WHERE a IN (SELECT a FROM t WHERE {body})"

        assert rebalance_sql(query) == query

    def test_a_plain_deep_chain_is_still_rebalanced(self):
        """The guard must not disarm the repair it sits next to."""
        assert rebalance_sql(_chain(512)) != _chain(512)


class TestColumnRefs:
    """Column extraction has to respect SQL quoting."""

    def test_backtick_quoted_names_are_found(self):
        query = (
            "SELECT * FROM logs WHERE Channel='Security' "
            "AND (`event.code`='4688' OR `winlog.event_data.Image` LIKE '%x%')"
        )

        assert column_refs(query) == {
            "Channel", "event.code", "winlog.event_data.Image"
        }

    def test_text_inside_string_literals_is_ignored(self):
        query = "SELECT * FROM logs WHERE CommandLine LIKE '%user=bob%' OR Image='x'"

        assert column_refs(query) == {"CommandLine", "Image"}

    def test_negated_comparisons_still_name_their_column(self):
        query = "SELECT * FROM logs WHERE CommandLine NOT LIKE '%a%' AND Image IS NOT NULL"

        assert column_refs(query) == {"CommandLine", "Image"}

    def test_double_quoted_and_bracketed_names_are_found(self):
        query = 'SELECT * FROM logs WHERE "odd name"=\'x\' AND [Data]=\'y\''

        assert column_refs(query) == {"odd name", "Data"}


class TestEventIdConstraints:
    """What a rule can match, read from the SQL that actually runs."""

    @pytest.mark.parametrize(
        "where,expected",
        [
            ("Channel='S' AND EventID=4688", {4688}),
            ("Channel='S' AND (EventID=4688 AND CommandLine LIKE '%a%')", {4688}),
            ("Channel='S' AND EventID IN (1,3,5)", {1, 3, 5}),
            ("Channel='S' AND (EventID=1 OR EventID=2)", {1, 2}),
            ("EventID='4688'", {4688}),
            ("`EventID`=4688", {4688}),
            # Unbounded: the rule may match an eventID this cannot name
            ("Channel='S' AND NOT (EventID=4624)", None),
            ("Channel='S' AND (EventID=4688 OR CommandLine LIKE '%m%')", None),
            ("Channel='S'", None),
            ("EventID BETWEEN 1 AND 5", None),
            ("EventID > 100", None),
        ],
    )
    def test_reads_the_bound_or_gives_up(self, where, expected):
        assert eventid_constraints([f"SELECT * FROM logs WHERE {where}"]) == expected

    def test_one_unbounded_statement_unbounds_the_rule(self):
        queries = [
            "SELECT * FROM logs WHERE EventID=1",
            "SELECT * FROM logs WHERE Channel='S'",
        ]

        assert eventid_constraints(queries) is None

    def test_statements_union_their_bounds(self):
        queries = [
            "SELECT * FROM logs WHERE EventID=1",
            "SELECT * FROM logs WHERE EventID=2",
        ]

        assert eventid_constraints(queries) == {1, 2}


class TestChannelConstraints:
    """Correlation rules carry no metadata, so their channel comes from SQL."""

    def test_channels_are_read_from_a_correlation_subquery(self):
        query = (
            "SELECT u, COUNT(*) AS c FROM (SELECT * FROM logs WHERE "
            "Channel='Security' AND EventID=4625) AS subquery "
            "GROUP BY u HAVING c >= 5"
        )

        assert channel_constraints([query]) == {"Security"}

    def test_an_unconstrained_channel_reads_as_unknown(self):
        query = (
            "SELECT u, COUNT(*) AS c FROM (SELECT * FROM logs WHERE "
            "EventID=4625) AS subquery GROUP BY u HAVING c >= 5"
        )

        assert channel_constraints([query]) is None

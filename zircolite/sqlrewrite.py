"""Re-associate over-deep OR chains in rule SQL so SQLite can parse them.

``pysigma-backend-sqlite`` emits value lists as a left-deep chain
(``a OR b OR c OR ...``), whose parse-tree depth equals the number of terms.
SQLite refuses anything past ``SQLITE_MAX_EXPR_DEPTH`` (1000 by default), so a
rule listing a few thousand hashes never runs at all. The limit cannot be
raised from Python: ``sqlite3_limit`` clamps to the compile-time bound, and
``Connection.setlimit`` only exists on Python 3.11+.

Re-emitting the same terms as a balanced binary tree brings the depth down to
O(log n) without touching the meaning of the expression.
"""

_CLOSERS = {"'": "'", '"': '"', "`": "`", "[": "]"}

# Below this, the chain cannot be what breached the depth limit, and wrapping
# it in parentheses would only make the SQL harder to read in --debug output.
_MIN_OR_TERMS = 8

_TAIL_KEYWORDS = ("GROUP", "ORDER", "LIMIT", "HAVING", "WINDOW")
_COMPOUND_KEYWORDS = ("UNION", "INTERSECT", "EXCEPT")


class _Unsupported(Exception):
    """The statement has a shape this rewriter does not model."""


def _quoted_span(sql: str, i: int):
    """Index just past the quoted run starting at ``i``, or None if none starts there."""
    char = sql[i]
    if char not in _CLOSERS:
        # A comment would swallow any parenthesis appended after it.
        if sql.startswith("--", i) or sql.startswith("/*", i):
            raise _Unsupported("comment")
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


def _is_word(sql: str, i: int, word: str) -> bool:
    """True when ``word`` sits at ``i`` as a whole token, case-insensitively."""
    if sql[i : i + len(word)].upper() != word:
        return False
    before = sql[i - 1] if i else " "
    after = sql[i + len(word)] if i + len(word) < len(sql) else " "
    return not (before.isalnum() or before == "_") and not (
        after.isalnum() or after == "_"
    )


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
    return _balance([part.strip() for part in operands])


def rebalance_sql(sql: str) -> str:
    """Return ``sql`` with deep OR chains re-associated into a balanced tree.

    Returns ``sql`` unchanged whenever the statement's shape is not one this
    can rewrite safely. Emitting subtly wrong SQL would be far worse than
    leaving a rule reported as broken, so every uncertainty bails out.
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

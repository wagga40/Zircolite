export type TokenKind = 'word' | 'quoted' | 'colon' | 'op' | 'minus' | 'lparen' | 'rparen' | 'or' | 'and';

export interface Token {
  kind: TokenKind;
  /** A quoted token holds its content, unescaped and without the quotes. */
  text: string;
  start: number;
  end: number;
  /** A field's quoted value with a * right before or after the quotes, as in CommandLine:*"net user"*. */
  starBefore?: boolean;
  starAfter?: boolean;
}

export class SearchError extends Error {
  constructor(message: string, readonly start: number, readonly end: number) {
    super(message);
    this.name = 'SearchError';
  }
}

const OPERATORS = ['>=', '<=', '>', '<', '='];

export function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  // Right after "field:" a value may hold colons: paths, times, IPv6 addresses.
  let valueNext = false;
  while (i < input.length) {
    const c = input[i];
    if (/\s/.test(c)) {
      i++;
      valueNext = false;
      continue;
    }
    if (valueNext && c === '*' && input[i + 1] === '"') {
      // Only a closed quote that ends the value, with or without a second *, makes a wildcard of the *:
      // anything else after it reads as one unquoted value, as it always has.
      const quoted = readQuoted(input, i + 1);
      const after = quoted === null ? -1 : quoted.end;
      const starAfter = after >= 0 && input[after] === '*' && endsValue(input, after + 1);
      if (quoted !== null && (starAfter || endsValue(input, after))) {
        const end = starAfter ? after + 1 : after;
        tokens.push({ kind: 'quoted', text: quoted.text, start: i, end, starBefore: true, ...(starAfter ? { starAfter } : {}) });
        i = end;
        valueNext = false;
        continue;
      }
    }
    if (c === '"') {
      const start = i;
      const quoted = readQuoted(input, i);
      if (quoted === null) {
        const escapedEnd = /\\"$/.test(input.slice(start, input.length).trimEnd());
        throw new SearchError(
          escapedEnd
            ? 'This quote is never closed: a backslash before a quote escapes it, so write \\\\ to end a value with a backslash'
            : 'This quote is never closed',
          start,
          input.length,
        );
      }
      i = quoted.end;
      const starAfter = valueNext && input[i] === '*' && endsValue(input, i + 1);
      if (starAfter) i++;
      tokens.push({ kind: 'quoted', text: quoted.text, start, end: i, ...(starAfter ? { starAfter } : {}) });
      valueNext = false;
      continue;
    }
    if (valueNext && c === '(') {
      throw new SearchError('Put parentheses around whole terms, as in (EventID:1 OR EventID:3)', i, i + 1);
    }
    if (c === '(' || c === ')') {
      tokens.push({ kind: c === '(' ? 'lparen' : 'rparen', text: c, start: i, end: i + 1 });
      i++;
      valueNext = false;
      continue;
    }
    if (c === ':' && !valueNext) {
      tokens.push({ kind: 'colon', text: c, start: i, end: i + 1 });
      i++;
      const op = OPERATORS.find((candidate) => input.startsWith(candidate, i));
      if (op) {
        tokens.push({ kind: 'op', text: op, start: i, end: i + op.length });
        i += op.length;
      }
      valueNext = true;
      continue;
    }
    if (c === '-' && !valueNext && (i === 0 || /[\s(]/.test(input[i - 1])) && i + 1 < input.length && !/\s/.test(input[i + 1])) {
      tokens.push({ kind: 'minus', text: c, start: i, end: i + 1 });
      i++;
      continue;
    }
    const start = i;
    // A value may hold balanced parentheses, as in Image:*foo(1).exe.
    let open = 0;
    while (i < input.length) {
      const ch = input[i];
      if (valueNext) {
        if (/\s/.test(ch) || (ch === ')' && open === 0)) break;
        if (ch === '(') open++;
        else if (ch === ')') open--;
      } else if (/[\s()":]/.test(ch)) break;
      i++;
    }
    const text = input.slice(start, i);
    const keyword = !valueNext && (text === 'OR' || text === 'AND');
    tokens.push({ kind: keyword ? (text === 'OR' ? 'or' : 'and') : 'word', text, start, end: i });
    valueNext = false;
  }
  return tokens;
}

/** The text of the quoted string opening at start, unescaped, and where it ends; null when it never closes. */
function readQuoted(input: string, start: number): { text: string; end: number } | null {
  let text = '';
  let i = start + 1;
  while (i < input.length && input[i] !== '"') {
    // Only \" and \\ are escapes; any other backslash is a path separator.
    if (input[i] === '\\' && (input[i + 1] === '"' || input[i + 1] === '\\')) {
      text += input[i + 1];
      i += 2;
    } else {
      text += input[i];
      i++;
    }
  }
  return i >= input.length ? null : { text, end: i + 1 };
}

function endsValue(input: string, i: number): boolean {
  return i >= input.length || /\s/.test(input[i]) || input[i] === ')';
}

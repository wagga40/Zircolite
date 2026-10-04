export type TokenKind = 'word' | 'quoted' | 'colon' | 'op' | 'minus' | 'lparen' | 'rparen' | 'or' | 'and';

export interface Token {
  kind: TokenKind;
  /** A quoted token holds its content, unescaped and without the quotes. */
  text: string;
  start: number;
  end: number;
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
    if (c === '"') {
      const start = i;
      let text = '';
      i++;
      while (i < input.length && input[i] !== '"') {
        if (input[i] === '\\' && i + 1 < input.length) {
          text += input[i + 1];
          i += 2;
        } else {
          text += input[i];
          i++;
        }
      }
      if (i >= input.length) throw new SearchError('This quote is never closed', start, input.length);
      i++;
      tokens.push({ kind: 'quoted', text, start, end: i });
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
    const stop = valueNext ? /[\s)]/ : /[\s()":]/;
    while (i < input.length && !stop.test(input[i])) i++;
    const text = input.slice(start, i);
    const keyword = !valueNext && (text === 'OR' || text === 'AND');
    tokens.push({ kind: keyword ? (text === 'OR' ? 'or' : 'and') : 'word', text, start, end: i });
    valueNext = false;
  }
  return tokens;
}

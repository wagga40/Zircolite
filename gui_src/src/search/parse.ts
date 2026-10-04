import { SearchError, type Token, tokenize } from './tokens';

export type Op = '=' | '>' | '>=' | '<' | '<=';

export type Node =
  | { kind: 'and' | 'or'; items: Node[]; start: number; end: number }
  | { kind: 'not'; item: Node; start: number; end: number }
  | {
      kind: 'term';
      /** null for a bare word or phrase, which searches every field. */
      field: string | null;
      /** A quoted field name always means a log field, never a shortcut. */
      fieldQuoted: boolean;
      op: Op;
      value: string;
      quoted: boolean;
      start: number;
      end: number;
    };

export function parse(input: string): Node | null {
  const tokens = tokenize(input);
  if (tokens.length === 0) return null;
  let pos = 0;
  const peek = (): Token | undefined => tokens[pos];
  const next = (): Token | undefined => tokens[pos++];
  const ends = (token: Token | undefined) => !token || token.kind === 'or' || token.kind === 'rparen' || token.kind === 'and';

  function orExpr(): Node {
    const items = [andExpr()];
    while (peek()?.kind === 'or') {
      const or = next() as Token;
      if (ends(peek())) throw new SearchError('OR needs a term on both sides', or.start, or.end);
      items.push(andExpr());
    }
    return items.length === 1 ? items[0] : { kind: 'or', items, start: items[0].start, end: items[items.length - 1].end };
  }

  function andExpr(): Node {
    const items = [unary()];
    for (;;) {
      const token = peek();
      if (!token || token.kind === 'or' || token.kind === 'rparen') break;
      if (token.kind === 'and') {
        next();
        if (ends(peek())) throw new SearchError('AND needs a term on both sides', token.start, token.end);
        continue;
      }
      items.push(unary());
    }
    return items.length === 1 ? items[0] : { kind: 'and', items, start: items[0].start, end: items[items.length - 1].end };
  }

  function unary(): Node {
    const token = peek();
    if (token?.kind === 'minus') {
      next();
      const item = unary();
      return { kind: 'not', item, start: token.start, end: item.end };
    }
    return primary();
  }

  function primary(): Node {
    const token = next();
    if (!token) throw new SearchError('A term is missing at the end', input.length, input.length);
    if (token.kind === 'lparen') {
      const after = peek();
      if (after?.kind === 'rparen') throw new SearchError('These parentheses are empty', token.start, after.end);
      const inner = orExpr();
      const close = next();
      if (close?.kind !== 'rparen') throw new SearchError('This parenthesis is never closed', token.start, token.end);
      return { ...inner, start: token.start, end: close.end };
    }
    if (token.kind === 'word' || token.kind === 'quoted') {
      if (peek()?.kind === 'colon') {
        const colon = next() as Token;
        let op: Op = '=';
        if (peek()?.kind === 'op') op = (next() as Token).text as Op;
        const value = next();
        if (!value || (value.kind !== 'word' && value.kind !== 'quoted')) {
          throw new SearchError(`A value is expected after "${token.text}:"`, token.start, colon.end);
        }
        return {
          kind: 'term', field: token.text, fieldQuoted: token.kind === 'quoted', op,
          value: value.text, quoted: value.kind === 'quoted', start: token.start, end: value.end,
        };
      }
      return { kind: 'term', field: null, fieldQuoted: false, op: '=', value: token.text, quoted: token.kind === 'quoted', start: token.start, end: token.end };
    }
    if (token.kind === 'colon') throw new SearchError('A field name is expected before ":"', token.start, token.end);
    if (token.kind === 'rparen') throw new SearchError('This parenthesis has no opening one', token.start, token.end);
    throw new SearchError(`"${token.text}" cannot start a term`, token.start, token.end);
  }

  const tree = orExpr();
  const extra = peek();
  if (extra) {
    throw new SearchError(extra.kind === 'rparen' ? 'This parenthesis has no opening one' : `Unexpected "${extra.text}"`, extra.start, extra.end);
  }
  return tree;
}

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LEVELS } from '../src/engine/levels';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { SHORTCUTS } from '../src/search/shortcuts';
import { tokenize } from '../src/search/tokens';
import { type Fixture, openFixture, schema } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

const run = (query: string) => db.uids(compile(parse(query), schema));
const A = 1, B = 2, CMD = 3, PS = 4294967297, OFF = 4294967298, PROC = 4294967299;

describe('tokenize', () => {
  it('reads fields, operators, quotes and keywords', () => {
    expect(tokenize('-EventID:>=4600 OR "a \\"b\\""').map((t) => [t.kind, t.text])).toEqual([
      ['minus', '-'], ['word', 'EventID'], ['colon', ':'], ['op', '>='], ['word', '4600'], ['or', 'OR'], ['quoted', 'a "b"'],
    ]);
  });

  it('keeps colons inside a value', () => {
    expect(tokenize('Image:C:\\x\\y.exe').map((t) => t.text)).toEqual(['Image', ':', 'C:\\x\\y.exe']);
  });

  it('keeps hyphens inside words', () => {
    expect(tokenize('a-b -c').map((t) => t.kind)).toEqual(['word', 'minus', 'word']);
  });

  it('reports an unclosed quote where it starts', () => {
    expect(() => tokenize('x "abc')).toThrowError(expect.objectContaining({ start: 2 }));
  });
});

describe('parse', () => {
  it('binds AND tighter than OR', () => {
    expect(parse('a b OR c')?.kind).toBe('or');
  });

  it.each([
    ['EventID:', /A value is expected/],
    ['(a OR b', /never closed/],
    ['a)', /no opening one/],
    ['OR a', /cannot start a term/],
    ['a OR', /OR needs a term on both sides/],
    [':x', /A field name is expected/],
    ['()', /empty/],
    ['Image:(a)', /parentheses around whole terms/],
  ])('rejects %s', (query, message) => {
    expect(() => parse(query)).toThrowError(message);
  });

  it('returns null for an empty query', () => {
    expect(parse('   ')).toBeNull();
  });
});

describe('compile against DuckDB', () => {
  it.each<[string, number[]]>([
    ['EventID:4624', [A]],
    ['computer:dc01', [A, B, PROC]],
    ['EventID:>4600', [A, B, PROC]],
    ['EventID:1 OR EventID:400', [CMD, PS, OFF]],
    ['Image:*\\cmd.exe', [CMD]],
    ['powershell', [PS, OFF]],
    ['"100% it\'s"', [PS]],
    ['50_off', [OFF]],
    ['Image:*0_off*', [OFF]],
    ['Image:*5_off*', []],
    ['"it\'s \\"odd\\"":x', [PS]],
    ['"level":error', [OFF]],
    ['level:>=high', [PS]],
    ['level:informational', [A]],
    ['rule:*powershell*', [PS]],
    ['rule:r-logon', [A]],
    ['tactic:discovery', [CMD]],
    ['tactic:Initial_Access', [A]],
    ['technique:T1059', [PS]],
    ['technique:t1033', [CMD]],
    ['host:WS02', [CMD, PS, OFF]],
    ['user:bob', [A]],
    ['(EventID:1 OR EventID:400) -host:ws02', []],
  ])('%s', async (query, expected) => {
    expect(await run(query)).toEqual(expected);
  });

  it('negation keeps events without the field', async () => {
    expect(await run('-Image:*cmd*')).toEqual([A, B, PS, OFF, PROC]);
  });

  it('literal matching ignores LIKE wildcards inside values', async () => {
    expect(await run('Image:"*cmd.exe"')).toEqual([]);
    expect(await run('CommandLine:*100%*')).toEqual([PS]);
  });

  it('injection attempts stay values', async () => {
    expect(await run('Computer:"x\' OR 1=1 --"')).toEqual([]);
    expect(await run("x' OR 1=1 --")).toEqual([]);
    expect(await run('"; DROP TABLE events; --"')).toEqual([]);
    expect(await db.rows('SELECT count(*) AS n FROM events')).toEqual([{ n: 6 }]);
  });

  it.each([
    ['nosuch:1', /No field named nosuch/],
    ['Comptuer:x', /did you mean Computer/],
    ['EventID:>abc', /needs a number/],
    ['Computer:>5', /holds text/],
    ['level:severe', /informational, low, medium, high, critical/],
    ['technique:1059', /T1234/],
  ])('explains %s', (query, message) => {
    expect(() => compile(parse(query), schema)).toThrowError(message);
  });

  it('every shortcut example compiles', () => {
    for (const shortcut of SHORTCUTS) expect(() => compile(parse(shortcut.example), schema)).not.toThrow();
  });

  it('an empty query matches everything', () => {
    expect(compile(null, schema)).toBe('TRUE');
  });

  it('keeps the level names in rank order', () => {
    expect(LEVELS).toEqual(['informational', 'low', 'medium', 'high', 'critical']);
  });
});

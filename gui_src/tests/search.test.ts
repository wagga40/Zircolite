import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LEVELS } from '../src/engine/levels';
import { compile } from '../src/search/compile';
import { hasFullText, parse } from '../src/search/parse';
import { SHORTCUTS } from '../src/search/shortcuts';
import { SearchError, tokenize } from '../src/search/tokens';
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

  it('keeps a lone backslash inside quotes', () => {
    expect(tokenize('"C:\\Windows\\x"').map((t) => t.text)).toEqual(['C:\\Windows\\x']);
    expect(tokenize('"a\\\\b \\"q\\""').map((t) => t.text)).toEqual(['a\\b "q"']);
  });

  it('keeps balanced parentheses inside an unquoted value', () => {
    expect(tokenize('Image:*foo(1).exe').map((t) => t.text)).toEqual(['Image', ':', '*foo(1).exe']);
    expect(tokenize('(Image:a OR Image:b)').map((t) => t.kind)).toEqual(
      ['lparen', 'word', 'colon', 'word', 'or', 'word', 'colon', 'word', 'rparen']);
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

  it.each([['('.repeat(10000)], ['-('.repeat(10000)]])('refuses absurd nesting', (query) => {
    expect(() => parse(query)).toThrowError(SearchError);
    expect(() => parse(query)).toThrowError(/nests too deeply/);
  });

  it('tells a search of every field from field searches', () => {
    expect(hasFullText(null)).toBe(false);
    expect(hasFullText(parse('EventID:1 -host:DC01'))).toBe(false);
    expect(hasFullText(parse('"level":error'))).toBe(false);
    expect(hasFullText(parse('mimikatz'))).toBe(true);
    expect(hasFullText(parse('EventID:1 -powershell'))).toBe(true);
    expect(hasFullText(parse('(Image:*cmd* OR "net user") EventID:1'))).toBe(true);
  });

  it('accepts reasonable nesting', () => {
    expect(parse(`${'('.repeat(60)}a${')'.repeat(60)}`)).not.toBeNull();
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
    ['level:<high', [A, CMD]],
    ['EventID:462*', [A]],
    ['Image:"C:\\Windows\\System32\\cmd.exe"', [CMD]],
    ['-rule:*powershell*', [A, B, CMD, OFF, PROC]],
    ['-host:ws02', [A, B, PROC]],
    ['level:informational', [A]],
    ['rule:*powershell*', [PS]],
    ['rule:r-logon', [A]],
    ['tactic:discovery', [CMD]],
    ['tactic:Initial_Access', [A]],
    ['tactic:"Privilege Escalation"', []],
    ['tactic:"Initial Access"', [A]],
    ['tactic:Persistence', [PS]],
    ['tactic:*access*', [A]],
    ['tactic:*s*', [A, CMD, PS]],
    ['tactic:defense-evasion', []],
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
    ['rule:>x', /only level compares/],
    ['tactic:>=discovery', /only level compares/],
    ['tactic:persistance', /No tactic named persistance; tactics are: reconnaissance, resource-development, .*, impact$/],
    ['tactic:*zzz*', /No tactic matches \*zzz\*; tactics are: reconnaissance, .*, impact$/],
    ['tactic:"*access*"', /No tactic named \*access\*/],
    ['technique:>=T1059', /only level compares/],
  ])('explains %s', (query, message) => {
    expect(() => compile(parse(query), schema)).toThrowError(message);
  });

  it('locates an error on its term', () => {
    expect(() => compile(parse('nosuch:1'), schema)).toThrowError(expect.objectContaining({ start: 0, end: 8 }));
    expect(() => compile(parse('a EventID:>abc'), schema)).toThrowError(expect.objectContaining({ start: 2, end: 14 }));
  });

  it('expands a tactic wildcard against the package\'s list', () => {
    expect(compile(parse('tactic:*access*'), schema)).toContain(`list_has_any(r.tactics, ['initial-access', 'credential-access'])`);
    expect(compile(parse('tactic:"Privilege Escalation"'), schema)).toContain(`list_contains(r.tactics, 'privilege-escalation')`);
    expect(compile(parse('tactic:Defense_Evasion'), schema)).toContain(`list_contains(r.tactics, 'stealth')`);
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

describe('the full-text index', () => {
  it.each([
    'powershell', '"100% it\'s"', '50_off', 'WS02', 'cmd*whoami', '"x\' OR 1=1"', 'DC01 -powershell', 'error', '"C:\\Tools"', 'ÀÉÎ',
  ])('the index finds exactly what the scan finds for %s', async (query) => {
    const tree = parse(query);
    expect(await db.uids(compile(tree, schema, { textIndex: true }))).toEqual(await db.uids(compile(tree, schema)));
  });

  it('reads the index only when told it is ready', () => {
    expect(compile(parse('powershell'), schema)).not.toContain('fulltext');
    expect(compile(parse('powershell'), schema, { textIndex: true })).toContain('FROM fulltext');
  });
});

describe('rulekey', () => {
  let twins: Fixture;
  beforeAll(async () => {
    twins = await openFixture([
      `INSERT INTO rules VALUES (4, 'R-LOGON', 'R-LOGON', 'Case twin', 'low', 1, 'd', [], [], [], [], 'x.yml', 'match', 0)`,
      `INSERT INTO rules VALUES (5, 'r-*', 'r-*', 'Star key', 'low', 1, 'd', [], [], [], [], 'y.yml', 'match', 0)`,
      'INSERT INTO hits VALUES (4, 2), (5, 3)',
    ]);
  });
  afterAll(() => twins.close());
  const keyed = (query: string) => twins.uids(compile(parse(query), schema));

  it('matches one key exactly, ignoring case twins and wildcards', async () => {
    expect(await keyed('rulekey:r-logon')).toEqual([A]);
    expect(await keyed('rulekey:R-LOGON')).toEqual([B]);
    expect(await keyed('rulekey:"r-*"')).toEqual([CMD]);
    expect(await keyed('rulekey:r-*')).toEqual([CMD]);
    expect(await keyed('rulekey:r-lo')).toEqual([]);
  });

  it('refuses a level comparison', () => {
    expect(() => compile(parse('rulekey:>x'), schema)).toThrowError(/only level compares/);
  });
});

describe('an unclosed quote', () => {
  it('explains how to end a value with a backslash', () => {
    expect(() => tokenize('Image:"C:\\dir\\"')).toThrowError(/write \\\\ to end a value with a backslash/);
    expect(() => tokenize('Image:"abc')).toThrowError(/^This quote is never closed$/);
  });
});

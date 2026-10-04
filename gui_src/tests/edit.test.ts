import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { compile } from '../src/search/compile';
import { appendRaw, appendTerm, chips, completionAt, fieldSuggestions, removeSpan } from '../src/search/edit';
import { parse } from '../src/search/parse';
import { type Fixture, openFixture, schema } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

describe('appendTerm', () => {
  it.each([
    ['', 'Computer', 'DC01', false, 'Computer:"DC01"'],
    ['powershell', 'Computer', 'DC01', true, 'powershell -Computer:"DC01"'],
    ['a OR b', 'EventID', '1', false, '(a OR b) EventID:"1"'],
    ['', 'level', 'error', false, '"level":"error"'],
    ['', 'it\'s "odd"', 'x\\y', false, '"it\'s \\"odd\\"":"x\\\\y"'],
  ])('appends to %j', (query, field, value, negate, expected) => {
    expect(appendTerm(query, field, value, negate)).toBe(expected);
  });

  it('appends a prepared term, wrapping a top-level OR', () => {
    expect(appendRaw('a OR b', 'rule:"x"')).toBe('(a OR b) rule:"x"');
    expect(appendRaw('  ', 'rule:"x"')).toBe('rule:"x"');
  });

  it.each<[string, string, number]>([
    ['Image', 'C:\\Windows\\System32\\cmd.exe', 3],
    ['EventID', '4624', 1],
    ['CommandLine', 'powershell -enc SQBFAFgA 100% it\'s', 4294967297],
    ['level', 'error', 4294967298],
    ['it\'s "odd"', 'x', 4294967297],
  ])('round-trips %s', async (field, value, uid) => {
    expect(await db.uids(compile(parse(appendTerm('', field, value, false)), schema))).toEqual([uid]);
  });
});

describe('chips and removeSpan', () => {
  it('lists top-level field terms', () => {
    const query = 'host:DC01 -EventID:4634 powershell';
    expect(chips(query)).toEqual([
      { label: 'host: DC01', negated: false, start: 0, end: 9 },
      { label: 'EventID: 4634', negated: true, start: 10, end: 23 },
    ]);
    expect(removeSpan(query, 10, 23)).toBe('host:DC01 powershell');
  });

  it('keeps the spacing inside quoted values', () => {
    expect(removeSpan('a:"x  y" b:1', 9, 12)).toBe('a:"x  y"');
  });

  it('returns no chips for a query that does not parse', () => {
    expect(chips('host:"open')).toEqual([]);
  });
});

describe('completion', () => {
  it('completes field names and shortcuts', () => {
    expect(completionAt('Comp', 4)).toEqual({ kind: 'field', prefix: 'Comp', start: 0, end: 4 });
    expect(fieldSuggestions('comp', schema)).toEqual(['Computer']);
    expect(fieldSuggestions('ho', schema)).toEqual(['host']);
  });

  it('completes values after a field', () => {
    expect(completionAt('Computer:DC', 11)).toEqual({ kind: 'value', field: 'Computer', prefix: 'DC', start: 9, end: 11 });
    expect(completionAt('Computer:', 9)).toEqual({ kind: 'value', field: 'Computer', prefix: '', start: 9, end: 9 });
  });

  it('stays quiet after a space', () => {
    expect(completionAt('Computer:DC01 ', 14)).toBeNull();
  });
});

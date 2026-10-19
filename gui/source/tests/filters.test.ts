import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { compile } from '../src/search/compile';
import {
  CellError, type ColumnFilter, cellText, columnState, parseCell, setColumnFilter, toTerms, withoutColumn,
} from '../src/search/filters';
import { parse } from '../src/search/parse';
import { type Fixture, openFixture, schema } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

const A = 1, B = 2, CMD = 3, PS = 4294967297, OFF = 4294967298, PROC = 4294967299;
const run = (query: string) => db.uids(compile(parse(query), schema));

const contains = (value: string, negate = false): ColumnFilter => ({ op: 'contains', value, negate });

describe('toTerms', () => {
  it.each<[string, ColumnFilter, string]>([
    ['CommandLine', contains('powershell'), 'CommandLine:*powershell*'],
    ['CommandLine', contains('net user'), 'CommandLine:*"net user"*'],
    ['CommandLine', contains('a"b'), 'CommandLine:*"a\\"b"*'],
    ['CommandLine', contains('a*b'), 'CommandLine:*"a*b"*'],
    ['CommandLine', contains('(x)'), 'CommandLine:*"(x)"*'],
    ['CommandLine', contains('-enc', true), '-CommandLine:*-enc*'],
    ['Image', { op: 'equals', value: 'cmd.exe', negate: false }, 'Image:cmd.exe'],
    ['Image', { op: 'equals', value: 'a b', negate: false }, 'Image:"a b"'],
    ['Image', { op: 'equals', value: '>5', negate: false }, 'Image:">5"'],
    ['Image', { op: 'equals', value: '', negate: false }, 'Image:""'],
    ['EventID', { op: 'equals', value: '4624', negate: true }, '-EventID:4624'],
    ['Image', { op: 'prefix', value: 'C:\\Windows', negate: false }, 'Image:C:\\Windows*'],
    ['Image', { op: 'prefix', value: 'C:\\Program Files', negate: false }, 'Image:"C:\\\\Program Files"*'],
    ['Image', { op: 'suffix', value: '\\cmd.exe', negate: false }, 'Image:*\\cmd.exe'],
    ['Image', { op: 'suffix', value: 'a b', negate: false }, 'Image:*"a b"'],
    ['Image', { op: 'pattern', value: 'C:*\\cmd*', negate: false }, 'Image:C:*\\cmd*'],
    ['EventID', { op: 'compare', bounds: [{ op: '>=', value: '1' }, { op: '<', value: '10' }], negate: false }, 'EventID:>=1 EventID:<10'],
    ['EventID', { op: 'compare', bounds: [{ op: '>', value: '5' }], negate: true }, '-EventID:>5'],
    ['EventID', { op: 'compare', bounds: [{ op: '>=', value: '1' }, { op: '<', value: '10' }], negate: true }, '-(EventID:>=1 EventID:<10)'],
    ['Image', { op: 'present', negate: false }, 'Image:*'],
    ['Image', { op: 'present', negate: true }, '-Image:*'],
    ['Image', { op: 'oneOf', values: ['a', 'b c'], negate: false }, '(Image:a OR Image:"b c")'],
    ['Image', { op: 'oneOf', values: ['a', 'b'], negate: true }, '-(Image:a OR Image:b)'],
    ['Image', { op: 'oneOf', values: ['a'], negate: false }, 'Image:a'],
    ['level', contains('x'), '"level":*x*'],
    ['OR', contains('x'), '"OR":*x*'],
    ["it's \"odd\"", contains('x'), '"it\'s \\"odd\\"":*x*'],
  ])('%s %j', (field, filter, expected) => {
    expect(toTerms(field, filter)).toBe(expected);
  });

  it('writes a shortcut column under its own name', () => {
    expect(toTerms('level', { op: 'compare', bounds: [{ op: '>=', value: 'high' }], negate: false }, { shortcut: true })).toBe('level:>=high');
  });
});

describe('a column filter matches what it says', () => {
  it.each<[string, ColumnFilter, number[]]>([
    ['CommandLine', contains('enc SQBF'), [PS]],
    ['CommandLine', contains('WHOAMI'), [CMD]],
    ['CommandLine', contains('100%'), [PS]],
    ['CommandLine', contains('whoami', true), [A, B, PS, OFF, PROC]],
    ['Image', { op: 'suffix', value: '\\cmd.exe', negate: false }, [CMD]],
    ['Image', { op: 'prefix', value: 'C:\\Windows\\', negate: false }, [CMD, PS]],
    ['Image', { op: 'present', negate: true }, [A, B, PROC]],
    ['Computer', { op: 'oneOf', values: ['dc01', 'nope'], negate: false }, [A, B, PROC]],
    ['Computer', { op: 'oneOf', values: ['dc01', 'nope'], negate: true }, [CMD, PS, OFF]],
    ['EventID', { op: 'compare', bounds: [{ op: '>=', value: '400' }, { op: '<', value: '4625' }], negate: false }, [A, OFF]],
    ['EventID', { op: 'compare', bounds: [{ op: '>=', value: '400' }, { op: '<', value: '4625' }], negate: true }, [B, CMD, PS, PROC]],
    ['EventID', { op: 'equals', value: '1', negate: false }, [CMD, PS]],
    ["it's \"odd\"", { op: 'equals', value: 'X', negate: false }, [PS]],
  ])('%s %j', async (field, filter, expected) => {
    expect(await run(toTerms(field, filter))).toEqual(expected);
  });
});

describe('columnState', () => {
  it('reads back every filter it writes', () => {
    const filters: [string, ColumnFilter][] = [
      ['CommandLine', contains('powershell')],
      ['CommandLine', contains('net user', true)],
      ['CommandLine', contains('a*b')],
      ['Image', { op: 'equals', value: 'cmd.exe', negate: false }],
      ['Image', { op: 'equals', value: 'a "b"', negate: true }],
      ['Image', { op: 'prefix', value: 'C:\\Program Files', negate: false }],
      ['Image', { op: 'suffix', value: '\\cmd.exe', negate: true }],
      ['Image', { op: 'pattern', value: 'C:*\\cmd*', negate: false }],
      ['EventID', { op: 'compare', bounds: [{ op: '>=', value: '1' }, { op: '<', value: '10' }], negate: false }],
      ['EventID', { op: 'compare', bounds: [{ op: '>=', value: '1' }, { op: '<', value: '10' }], negate: true }],
      ['EventID', { op: 'compare', bounds: [{ op: '<=', value: '7' }], negate: false }],
      ['Image', { op: 'present', negate: false }],
      ['Image', { op: 'present', negate: true }],
      ['Image', { op: 'oneOf', values: ['a', 'b c', 'd'], negate: false }],
      ['Image', { op: 'oneOf', values: ['a', 'b'], negate: true }],
      ['level', contains('x')],
    ];
    for (const [field, filter] of filters) {
      const query = `x ${toTerms(field, filter)} y`;
      const state = columnState(query, field);
      expect(state.kind === 'filter' && state.filter, query).toEqual(filter);
      const spans = state.kind === 'filter' ? state.spans : [];
      expect([spans[0][0], spans[spans.length - 1][1]], query).toEqual([2, query.length - 2]);
    }
  });

  it.each<[string, string, unknown]>([
    ['', 'Image', { kind: 'none' }],
    ['powershell', 'Image', { kind: 'none' }],
    ['a image:*cmd* b', 'Image', { kind: 'filter', filter: contains('cmd'), spans: [[2, 13]] }],
    ['IMAGE:"x"', 'Image', { kind: 'filter', filter: { op: 'equals', value: 'x', negate: false }, spans: [[0, 9]] }],
    ['Image:*a* Image:*b*', 'Image', { kind: 'custom', text: 'Image:*a* Image:*b*', spans: [[0, 9], [10, 19]] }],
    ['Image:x z -Image:y', 'Image', { kind: 'custom', text: 'Image:x -Image:y', spans: [[0, 7], [10, 18]] }],
    ['(Image:a OR Image:*b*)', 'Image', { kind: 'custom', text: '(Image:a OR Image:*b*)', spans: [[0, 22]] }],
    ['EventID:>1 EventID:>5', 'EventID', { kind: 'custom', text: 'EventID:>1 EventID:>5', spans: [[0, 10], [11, 21]] }],
    ['(Image:x OR User:y)', 'Image', { kind: 'none' }],
    ['a OR Image:x', 'Image', { kind: 'none' }],
    ['(Image:a OR Image:b)', 'Image', { kind: 'filter', filter: { op: 'oneOf', values: ['a', 'b'], negate: false }, spans: [[0, 20]] }],
    ['level:high', 'level', { kind: 'none' }],
    ['"level":high', 'level', { kind: 'filter', filter: { op: 'equals', value: 'high', negate: false }, spans: [[0, 12]] }],
    ['host:dc01', 'host', { kind: 'none' }],
    ['Image:"open', 'Image', { kind: 'invalid' }],
  ])('%j on %s', (query, field, expected) => {
    expect(columnState(query, field)).toEqual(expected);
  });

  it('reads a shortcut column only from its unquoted shortcut', () => {
    expect(columnState('level:>=high "level":x', 'level', { shortcut: true })).toEqual({
      kind: 'filter', filter: { op: 'compare', bounds: [{ op: '>=', value: 'high' }], negate: false }, spans: [[0, 12]],
    });
  });
});

describe('setColumnFilter', () => {
  it.each<[string, string, ColumnFilter | null, string]>([
    ['a Image:*x* b', 'Image', contains('y'), 'a Image:*y* b'],
    ['a   Image:*x*   b', 'Image', contains('y'), 'a   Image:*y*   b'],
    ['a AND Image:*x*', 'Image', null, 'a'],
    ['Image:*a* x Image:*b*', 'Image', contains('c'), 'Image:*c* x'],
    ['Image:*a* AND x AND Image:*b*', 'Image', null, 'x'],
    ['a OR b', 'Image', contains('c'), '(a OR b) Image:*c*'],
    ['', 'Image', contains('c'), 'Image:*c*'],
    ['x', 'Image', null, 'x'],
    ['x EventID:>3', 'EventID', { op: 'compare', bounds: [{ op: '>=', value: '1' }, { op: '<', value: '9' }], negate: false }, 'x EventID:>=1 EventID:<9'],
    ['(Image:a OR Image:b) z', 'Image', { op: 'oneOf', values: ['a', 'b', 'c'], negate: false }, '(Image:a OR Image:b OR Image:c) z'],
  ])('%j on %s', (query, field, filter, expected) => {
    expect(setColumnFilter(query, field, filter)).toBe(expected);
    expect(() => parse(expected)).not.toThrow();
  });

  it('refuses a query that does not parse', () => {
    expect(() => setColumnFilter('Image:"open', 'Image', contains('x'))).toThrow();
  });

  it('takes a column out of a query, leaving the rest', () => {
    expect(withoutColumn('EventID:>=1 x EventID:<10', 'EventID')).toBe('x');
    expect(withoutColumn('x', 'EventID')).toBe('x');
  });
});

describe('parseCell and cellText', () => {
  it.each<[string, boolean, ColumnFilter | null]>([
    ['powershell', false, contains('powershell')],
    ['  powershell ', false, contains('powershell')],
    ['net user', false, contains('net user')],
    ['-enc', false, contains('-enc')],
    ['4624', true, { op: 'equals', value: '4624', negate: false }],
    ['4624', false, contains('4624')],
    ['=cmd.exe', false, { op: 'equals', value: 'cmd.exe', negate: false }],
    ['= a b', false, { op: 'equals', value: 'a b', negate: false }],
    ['cmd*', false, { op: 'prefix', value: 'cmd', negate: false }],
    ['*\\cmd.exe', false, { op: 'suffix', value: '\\cmd.exe', negate: false }],
    ['*x*', false, contains('x')],
    ['a*b', false, { op: 'pattern', value: 'a*b', negate: false }],
    ['"a*b"', false, contains('a*b')],
    ['"say \\"hi\\""', false, contains('say "hi"')],
    ['"net user"*', false, { op: 'prefix', value: 'net user', negate: false }],
    ['*"x y"', false, { op: 'suffix', value: 'x y', negate: false }],
    ['*"x y"*', false, contains('x y')],
    ['>4600', true, { op: 'compare', bounds: [{ op: '>', value: '4600' }], negate: false }],
    ['>= 1 < 10', true, { op: 'compare', bounds: [{ op: '>=', value: '1' }, { op: '<', value: '10' }], negate: false }],
    ['!x', false, contains('x', true)],
    ['!=x', false, { op: 'equals', value: 'x', negate: true }],
    ['!>5', true, { op: 'compare', bounds: [{ op: '>', value: '5' }], negate: true }],
    ['*', false, { op: 'present', negate: false }],
    ['!*', false, { op: 'present', negate: true }],
    ['', false, null],
    ['   ', false, null],
  ])('%j (numeric %s)', (text, numeric, expected) => {
    expect(parseCell(text, numeric)).toEqual(expected);
  });

  it.each([
    ['a*b c', /cannot hold spaces/],
    ['!', /Nothing/],
    ['=', /Nothing/],
    ['>=1 >=2', /one lower and one upper/],
    ['>1 <2 <3', /one lower and one upper/],
    ['"open', /never closed/],
  ])('refuses %j', (text, message) => {
    expect(() => parseCell(text, true)).toThrowError(CellError);
    expect(() => parseCell(text, true)).toThrowError(message);
  });

  it('writes every filter so that it reads back the same', () => {
    const filters: [ColumnFilter, boolean][] = [
      [contains('powershell'), false],
      [contains('net user', true), false],
      [contains('4624'), true],
      [contains('=x'), false],
      [contains('!x'), false],
      [contains('>3'), false],
      [contains('a*b'), false],
      [contains('"q"'), false],
      [contains(' padded '), false],
      [{ op: 'equals', value: 'cmd.exe', negate: false }, false],
      [{ op: 'equals', value: '4624', negate: true }, true],
      [{ op: 'prefix', value: 'C:\\Program Files', negate: false }, false],
      [{ op: 'suffix', value: '\\cmd.exe', negate: false }, false],
      [{ op: 'pattern', value: 'a*b', negate: true }, false],
      [{ op: 'compare', bounds: [{ op: '>=', value: '1' }, { op: '<', value: '10' }], negate: false }, true],
      [{ op: 'present', negate: true }, false],
    ];
    for (const [filter, numeric] of filters) {
      const text = cellText({ kind: 'filter', filter, spans: [] }, numeric);
      expect(parseCell(text, numeric), text).toEqual(filter);
    }
  });

  it('summarises what a cell cannot show as typed', () => {
    expect(cellText({ kind: 'filter', filter: { op: 'oneOf', values: ['a', 'b', 'c'], negate: false }, spans: [] }, false)).toBe('3 values');
    expect(cellText({ kind: 'filter', filter: { op: 'oneOf', values: ['a', 'b'], negate: true }, spans: [] }, false)).toBe('not 2 values');
    expect(cellText({ kind: 'custom', text: 'Image:*a* Image:*b*', spans: [] }, false)).toBe('Image:*a* Image:*b*');
    expect(cellText({ kind: 'none' }, false)).toBe('');
  });
});
